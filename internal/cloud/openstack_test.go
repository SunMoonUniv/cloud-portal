package cloud

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/quotasets"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/users"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/quotas"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
)

// 실제 OpenStack에 시험 계정(it-…)을 만들고 지운다. node01에서 관리자 환경 변수로 돌린다.
//
//	source /etc/kolla/admin-openrc.sh && PORTAL_IT=1 go test ./internal/cloud/ -run OpenStack -v
func TestOpenStack(t *testing.T) {
	if os.Getenv("PORTAL_IT") != "1" {
		t.Skip("PORTAL_IT=1일 때만 실제 OpenStack으로 시험한다")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	o, err := NewOpenStack(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	login := "it-" + hex.EncodeToString(b)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		_ = o.DeleteStudent(ctx, login)
	})

	s := Student{Login: login, Name: "시험", Quota: DefaultQuota, Enabled: true}
	acct, err := o.EnsureStudent(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	again, err := o.EnsureStudent(ctx, s)
	if err != nil || again != acct {
		t.Fatalf("두 번째 EnsureStudent: %+v %v", again, err)
	}

	// 할당량
	cq, err := quotasets.Get(ctx, o.compute, acct.ProjectID).Extract()
	if err != nil || cq.Instances != 2 || cq.Cores != 2 || cq.RAM != 4096 {
		t.Fatalf("Nova 할당량: %+v %v", cq, err)
	}
	nq, err := quotas.Get(ctx, o.network, acct.ProjectID).Extract()
	if err != nil || nq.FloatingIP != 1 || nq.Network != 0 || nq.Router != 0 || nq.Port != 10 {
		t.Fatalf("Neutron 할당량: %+v %v", nq, err)
	}

	// 기본 보안 그룹: LAN 출발지마다 22와 ICMP, 두 번 불러도 겹치지 않는다
	page, err := groups.List(o.network, groups.ListOpts{ProjectID: acct.ProjectID, Name: "default"}).AllPages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sgs, _ := groups.ExtractGroups(page)
	page, err = rules.List(o.network, rules.ListOpts{SecGroupID: sgs[0].ID, Direction: "ingress", EtherType: "IPv4"}).AllPages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := rules.ExtractRules(page)
	var lan []string
	for _, r := range rs {
		if r.RemoteIPPrefix != "" {
			lan = append(lan, r.Protocol+" "+r.RemoteIPPrefix)
		}
	}
	if len(lan) != 2*len(LANSources) {
		t.Fatalf("LAN 규칙 %d개(기대 %d): %v", len(lan), 2*len(LANSources), lan)
	}

	// 비밀번호를 넣으면 그 비밀번호로 로그인되고, 끄면 막힌다
	if err := o.SetPassword(ctx, acct.UserID, "It-pass-12345"); err != nil {
		t.Fatal(err)
	}
	if err := studentLogin(ctx, login, "It-pass-12345"); err != nil {
		t.Fatalf("학생 로그인: %v", err)
	}
	// 학생이 스스로 바꾸려 하면 거부된다(lock_password). 웹 콘솔의 비밀번호 바꾸기도 이 API를 쓴다.
	err = users.ChangePassword(ctx, o.identity, acct.UserID, users.ChangePasswordOpts{
		OriginalPassword: "It-pass-12345", Password: "Self-change-678",
	}).ExtractErr()
	if err == nil {
		t.Fatal("학생이 스스로 비밀번호를 바꿨다")
	}
	if err := studentLogin(ctx, login, "It-pass-12345"); err != nil {
		t.Fatalf("거부된 뒤 원래 비밀번호로 로그인: %v", err)
	}
	if err := o.SetEnabled(ctx, acct.UserID, false); err != nil {
		t.Fatal(err)
	}
	if err := studentLogin(ctx, login, "It-pass-12345"); err == nil {
		t.Fatal("끈 사용자가 로그인됐다")
	}
	if _, err := o.EnsureStudent(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := studentLogin(ctx, login, "It-pass-12345"); err != nil {
		t.Fatalf("다시 켠 뒤 로그인: %v", err)
	}

	if u, err := o.Usage(ctx, acct.ProjectID); err != nil || u != (Usage{}) {
		t.Fatalf("사용량: %+v %v", u, err)
	}
	ps, err := o.ListStudentProjects(ctx)
	if err != nil || !slices.ContainsFunc(ps, func(p Project) bool { return p.Login == login }) {
		t.Fatalf("학생 프로젝트 목록에 없다: %v", err)
	}

	// 학생이 아닌 계정(admin)은 만들지도 지우지도 않는다
	if _, err := o.EnsureStudent(ctx, Student{Login: "admin", Name: "x", Quota: DefaultQuota, Enabled: true}); !errors.Is(err, ErrNotStudent) {
		t.Fatalf("admin으로 EnsureStudent: %v", err)
	}
	if p, _ := o.findProject(ctx, "admin"); p != nil {
		t.Fatal("student-admin 프로젝트가 생겼다")
	}
	if err := o.DeleteStudent(ctx, "admin"); !errors.Is(err, ErrNotStudent) {
		t.Fatalf("admin으로 DeleteStudent: %v", err)
	}

	if err := o.DeleteStudent(ctx, login); err != nil {
		t.Fatal(err)
	}
	if p, _ := o.findProject(ctx, login); p != nil {
		t.Fatal("프로젝트가 남았다")
	}
	if u, _ := o.findUser(ctx, login); u != nil {
		t.Fatal("사용자가 남았다")
	}
}

func studentLogin(ctx context.Context, login, password string) error {
	_, err := openstack.AuthenticatedClient(ctx, gophercloud.AuthOptions{
		IdentityEndpoint: os.Getenv("OS_AUTH_URL"), Username: login, Password: password,
		DomainName: "Default", TenantName: ProjectPrefix + login,
	})
	return err
}

// 실제 VM을 하나 만들어 켜기·끄기·유동 IP·지우기를 거친다(1~2분).
func TestOpenStackVM(t *testing.T) {
	if os.Getenv("PORTAL_IT") != "1" {
		t.Skip("PORTAL_IT=1일 때만 실제 OpenStack으로 시험한다")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	o, err := NewOpenStack(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	login := "it-" + hex.EncodeToString(b)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		_ = o.DeleteStudent(ctx, login)
	})
	acct, err := o.EnsureStudent(ctx, Student{Login: login, Name: "VM 시험", Quota: DefaultQuota, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := o.Flavors(ctx)
	if err != nil || len(fs) != 3 || fs[0].Name != "s.tiny" {
		t.Fatalf("크기 목록: %+v %v", fs, err)
	}

	vm, err := o.CreateVM(ctx, acct.ProjectID, VMRequest{Name: "it1", Flavor: "s.tiny", SSHKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGv0Y4wQ2m7c3rN9b0Gq9hW7aZQ2tKJw5zW8b2v8yX1p it"})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.WaitActive(ctx, acct.ProjectID, vm.ID); err != nil {
		t.Fatal(err)
	}
	// vCPU 2 중 1을 쓰고 있으므로 s.small(2)은 할당량 초과. 첫 VM이 만들어지는 중일 때는 Nova가 API에서
	// 바로 거부하지 않고 나중에 다시 세어 오류 상태로 만들기도 하므로, 켜진 뒤에 확인한다.
	if _, err := o.CreateVM(ctx, acct.ProjectID, VMRequest{Name: "it2", Flavor: "s.small", SSHKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGv0Y4wQ2m7c3rN9b0Gq9hW7aZQ2tKJw5zW8b2v8yX1p it"}); !errors.Is(err, ErrQuota) {
		t.Fatalf("할당량 초과가 ErrQuota가 아니다: %v", err)
	}
	ip, err := o.AttachFloatingIP(ctx, acct.ProjectID, vm.ID)
	if err != nil || ip == "" {
		t.Fatalf("유동 IP: %q %v", ip, err)
	}
	vms, err := o.ListVMs(ctx, acct.ProjectID)
	if err != nil || len(vms) != 1 || vms[0].FloatingIP != ip || vms[0].Flavor != "s.tiny" || vms[0].FixedIP == "" {
		t.Fatalf("VM 목록: %+v %v", vms, err)
	}
	t.Logf("VM %s: %s, 내부 %s, 유동 %s", vm.ID, vms[0].Status, vms[0].FixedIP, ip)

	waitStatus := func(want string) {
		t.Helper()
		for range 60 {
			vms, err := o.ListVMs(ctx, acct.ProjectID)
			if err == nil && len(vms) == 1 && vms[0].Status == want && vms[0].TaskState == "" {
				return
			}
			time.Sleep(3 * time.Second)
		}
		t.Fatalf("%s가 되지 않았다", want)
	}
	if err := o.VMAction(ctx, acct.ProjectID, vm.ID, "stop"); err != nil {
		t.Fatal(err)
	}
	waitStatus("SHUTOFF")
	if err := o.VMAction(ctx, acct.ProjectID, vm.ID, "stop"); !errors.Is(err, ErrState) {
		t.Fatalf("꺼진 VM 끄기가 ErrState가 아니다: %v", err)
	}
	if err := o.VMAction(ctx, acct.ProjectID, vm.ID, "start"); err != nil {
		t.Fatal(err)
	}
	waitStatus("ACTIVE")

	if err := o.DetachFloatingIP(ctx, acct.ProjectID, vm.ID); err != nil {
		t.Fatal(err)
	}
	if vms, _ := o.ListVMs(ctx, acct.ProjectID); len(vms) != 1 || vms[0].FloatingIP != "" {
		t.Fatalf("떼었는데 유동 IP가 남았다: %+v", vms)
	}
	if _, err := o.AttachFloatingIP(ctx, acct.ProjectID, vm.ID); err != nil {
		t.Fatal(err)
	}
	if err := o.DeleteVM(ctx, acct.ProjectID, vm.ID); err != nil {
		t.Fatal(err)
	}
	if u, err := o.Usage(ctx, acct.ProjectID); err != nil || u.FloatingIPs != 0 {
		t.Fatalf("지운 뒤 유동 IP가 남았다: %+v %v", u, err)
	}
	for range 60 {
		if vms, _ := o.ListVMs(ctx, acct.ProjectID); len(vms) == 0 {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatal("VM이 지워지지 않았다")
}
