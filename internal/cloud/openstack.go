package cloud

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/quotasets"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/users"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/quotas"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
)

// Keystone 사용자 옵션. gophercloud에 상수가 없어 이름을 직접 쓴다.
const lockPassword users.Option = "lock_password"

// OpenStack은 관리자 권한(Keystone 사용자 cloud-portal, admin 프로젝트의 admin 역할)으로 API를 부른다.
type OpenStack struct {
	identity, compute, network, image *gophercloud.ServiceClient
	domainID                          string
	memberRoleID                      string
	selfID                            string // 포털 자신의 Keystone 사용자 ID
	studentNetID, publicNetID         string

	auth     gophercloud.AuthOptions // 프로젝트별 접속에 다시 쓴다
	eo       gophercloud.EndpointOpts
	pmu      sync.Mutex
	projects map[string]*projectClients
}

// NewOpenStack은 OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_PROJECT_NAME(그리고 있으면
// OS_USER_DOMAIN_NAME, OS_REGION_NAME, OS_INTERFACE) 환경 변수로 접속한다.
func NewOpenStack(ctx context.Context) (*OpenStack, error) {
	for _, k := range []string{"OS_AUTH_URL", "OS_USERNAME", "OS_PASSWORD", "OS_PROJECT_NAME"} {
		if os.Getenv(k) == "" {
			return nil, fmt.Errorf("환경 변수 %s가 없다", k)
		}
	}
	domain := firstSet(os.Getenv("OS_USER_DOMAIN_NAME"), os.Getenv("OS_DOMAIN_NAME"), "Default")
	o := &OpenStack{
		auth: gophercloud.AuthOptions{
			IdentityEndpoint: os.Getenv("OS_AUTH_URL"),
			Username:         os.Getenv("OS_USERNAME"),
			Password:         os.Getenv("OS_PASSWORD"),
			DomainName:       domain,
			AllowReauth:      true,
		},
		eo: gophercloud.EndpointOpts{
			Region:       os.Getenv("OS_REGION_NAME"),
			Availability: gophercloud.Availability(firstSet(os.Getenv("OS_INTERFACE"), "internal")),
		},
		projects: map[string]*projectClients{},
	}
	adminAuth := o.auth
	adminAuth.TenantName = os.Getenv("OS_PROJECT_NAME")
	provider, err := openstack.AuthenticatedClient(ctx, adminAuth)
	if err != nil {
		return nil, fmt.Errorf("Keystone 로그인: %w", err)
	}
	provider.HTTPClient = http.Client{Timeout: 60 * time.Second}
	eo := o.eo
	if o.identity, err = openstack.NewIdentityV3(provider, eo); err != nil {
		return nil, err
	}
	if o.compute, err = openstack.NewComputeV2(provider, eo); err != nil {
		return nil, err
	}
	// 다른 사용자의 키페어를 보고 지우려면 2.10 이상이 필요하다.
	o.compute.Microversion = "2.10"
	if o.network, err = openstack.NewNetworkV2(provider, eo); err != nil {
		return nil, err
	}
	if o.image, err = openstack.NewImageV2(provider, eo); err != nil {
		return nil, err
	}

	page, err := roles.List(o.identity, roles.ListOpts{Name: MemberRole}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("역할 목록: %w", err)
	}
	rs, err := roles.ExtractRoles(page)
	if err != nil || len(rs) != 1 {
		return nil, fmt.Errorf("역할 %s를 찾지 못했다", MemberRole)
	}
	o.memberRoleID = rs[0].ID
	if o.domainID, err = o.lookupDomainID(ctx, domain); err != nil {
		return nil, err
	}
	self, err := o.findUser(ctx, o.auth.Username)
	if err != nil || self == nil {
		return nil, fmt.Errorf("포털 자신의 사용자 %s를 찾지 못했다: %v", o.auth.Username, err)
	}
	o.selfID = self.ID
	if o.studentNetID, err = o.networkID(ctx, StudentNet); err != nil {
		return nil, err
	}
	if o.publicNetID, err = o.networkID(ctx, PublicNet); err != nil {
		return nil, err
	}
	return o, nil
}

func firstSet(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// lookupDomainID는 Default 도메인의 ID를 admin 프로젝트에서 읽는다(도메인 API 권한 없이).
func (o *OpenStack) lookupDomainID(ctx context.Context, domain string) (string, error) {
	if strings.EqualFold(domain, "Default") {
		return "default", nil
	}
	return "", fmt.Errorf("도메인 %s는 지원하지 않는다(Default만)", domain)
}

func (o *OpenStack) findProject(ctx context.Context, login string) (*projects.Project, error) {
	page, err := projects.List(o.identity, projects.ListOpts{Name: ProjectPrefix + login, DomainID: o.domainID}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := projects.ExtractProjects(page)
	if err != nil || len(ps) == 0 {
		return nil, err
	}
	p := ps[0]
	if !slices.Contains(p.Tags, StudentTag) {
		return nil, fmt.Errorf("프로젝트 %s: %w", p.Name, ErrNotStudent)
	}
	return &p, nil
}

func (o *OpenStack) findUser(ctx context.Context, login string) (*users.User, error) {
	page, err := users.List(o.identity, users.ListOpts{Name: login, DomainID: o.domainID}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	us, err := users.ExtractUsers(page)
	if err != nil || len(us) == 0 {
		return nil, err
	}
	return &us[0], nil
}

func (o *OpenStack) EnsureStudent(ctx context.Context, s Student) (Account, error) {
	var acct Account
	p, err := o.findProject(ctx, s.Login)
	if err != nil {
		return acct, err
	}
	u, err := o.findUser(ctx, s.Login)
	if err != nil {
		return acct, err
	}
	// 같은 이름의 사용자가 있는데 이 학생 프로젝트 사람이 아니면(admin, 서비스 계정 등) 아무것도 만들기 전에 멈춘다.
	if u != nil && (p == nil || u.DefaultProjectID != p.ID) {
		return acct, fmt.Errorf("사용자 %s: %w", s.Login, ErrNotStudent)
	}
	if p == nil {
		p, err = projects.Create(ctx, o.identity, projects.CreateOpts{
			Name: ProjectPrefix + s.Login, DomainID: o.domainID, Description: s.Name, Tags: []string{StudentTag},
		}).Extract()
		if err != nil {
			return acct, fmt.Errorf("프로젝트 만들기: %w", err)
		}
	} else if p.Description != s.Name {
		desc := s.Name
		if _, err := projects.Update(ctx, o.identity, p.ID, projects.UpdateOpts{Description: &desc}).Extract(); err != nil {
			return acct, fmt.Errorf("프로젝트 설명: %w", err)
		}
	}
	acct.ProjectID = p.ID

	enabled := s.Enabled
	// lock_password: 학생은 웹 콘솔·API에서 자기 비밀번호를 바꾸지 못한다(Keystone이 거부). 관리자(포털)는 바꿀 수 있다.
	// 이렇게 해서 포털 비밀번호와 웹 콘솔 비밀번호가 어긋나지 않게 한다. Keystone 정책으로는 막을 수 없다
	// (비밀번호 변경 API는 정책을 검사하지 않는다).
	locked := map[users.Option]any{lockPassword: true}
	if u == nil {
		// 비밀번호 없이 만든다. 학생이 포털에 비밀번호를 입력할 때 같은 값으로 넣는다.
		u, err = users.Create(ctx, o.identity, users.CreateOpts{
			Name: s.Login, DomainID: o.domainID, DefaultProjectID: p.ID, Description: s.Name, Enabled: &enabled,
			Options: locked,
		}).Extract()
		if err != nil {
			return acct, fmt.Errorf("사용자 만들기: %w", err)
		}
	} else if u.Enabled != enabled || u.Description != s.Name || u.Options[string(lockPassword)] != true {
		desc := s.Name
		if _, err := users.Update(ctx, o.identity, u.ID, users.UpdateOpts{
			Enabled: &enabled, Description: &desc, Options: locked,
		}).Extract(); err != nil {
			return acct, fmt.Errorf("사용자 고치기: %w", err)
		}
	}
	acct.UserID = u.ID

	// 역할 부여는 이미 있어도 오류가 나지 않는다. 포털 자신도 member로 넣어, 학생 대신 VM을 다룰 수 있게 한다.
	for _, who := range []string{u.ID, o.selfID} {
		if err := roles.Assign(ctx, o.identity, o.memberRoleID, roles.AssignOpts{UserID: who, ProjectID: p.ID}).ExtractErr(); err != nil {
			return acct, fmt.Errorf("역할 부여: %w", err)
		}
	}
	if err := o.setQuota(ctx, p.ID, s.Quota); err != nil {
		return acct, err
	}
	if err := o.ensureSecurityGroup(ctx, p.ID); err != nil {
		return acct, err
	}
	return acct, nil
}

func (o *OpenStack) setQuota(ctx context.Context, projectID string, q Quota) error {
	ptr := func(v int) *int { return &v }
	if _, err := quotasets.Update(ctx, o.compute, projectID, quotasets.UpdateOpts{
		Instances: ptr(q.Instances), Cores: ptr(q.Cores), RAM: ptr(q.RAMMB),
	}).Extract(); err != nil {
		return fmt.Errorf("Nova 할당량: %w", err)
	}
	if _, err := quotas.Update(ctx, o.network, projectID, quotas.UpdateOpts{
		FloatingIP: ptr(q.FloatingIPs), Network: ptr(quotaNetworks), Subnet: ptr(quotaSubnets), Router: ptr(quotaRouters),
		Port: ptr(quotaPorts), SecurityGroup: ptr(quotaSecGroups), SecurityGroupRule: ptr(quotaSecGroupRules),
	}).Extract(); err != nil {
		return fmt.Errorf("Neutron 할당량: %w", err)
	}
	return nil
}

// ensureSecurityGroup은 기본 보안 그룹에 22와 ICMP 규칙을 LANSources마다 넣는다. 있는 규칙은 건너뛴다.
func (o *OpenStack) ensureSecurityGroup(ctx context.Context, projectID string) error {
	// 관리자가 프로젝트를 지정해 조회하면 Neutron이 그 프로젝트의 기본 보안 그룹을 만든다.
	page, err := groups.List(o.network, groups.ListOpts{ProjectID: projectID, Name: "default"}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("보안 그룹 목록: %w", err)
	}
	sgs, err := groups.ExtractGroups(page)
	if err != nil {
		return err
	}
	if len(sgs) == 0 {
		return fmt.Errorf("프로젝트 %s의 기본 보안 그룹이 없다", projectID)
	}
	sg := sgs[0]
	page, err = rules.List(o.network, rules.ListOpts{SecGroupID: sg.ID}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("보안 그룹 규칙 목록: %w", err)
	}
	existing, err := rules.ExtractRules(page)
	if err != nil {
		return err
	}
	has := func(proto string, port int, src string) bool {
		for _, r := range existing {
			if r.Direction == "ingress" && r.EtherType == "IPv4" && r.Protocol == proto &&
				r.PortRangeMin == port && r.PortRangeMax == port && r.RemoteIPPrefix == src {
				return true
			}
		}
		return false
	}
	for _, src := range LANSources {
		want := []rules.CreateOpts{
			{Protocol: rules.ProtocolTCP, PortRangeMin: 22, PortRangeMax: 22},
			{Protocol: rules.ProtocolICMP},
		}
		for _, w := range want {
			if has(string(w.Protocol), w.PortRangeMin, src) {
				continue
			}
			w.Direction, w.EtherType, w.SecGroupID, w.RemoteIPPrefix = rules.DirIngress, rules.EtherType4, sg.ID, src
			if _, err := rules.Create(ctx, o.network, w).Extract(); err != nil {
				return fmt.Errorf("보안 그룹 규칙(%s %s): %w", w.Protocol, src, err)
			}
		}
	}
	return nil
}

func (o *OpenStack) SetEnabled(ctx context.Context, userID string, enabled bool) error {
	_, err := users.Update(ctx, o.identity, userID, users.UpdateOpts{Enabled: &enabled}).Extract()
	return err
}

func (o *OpenStack) SetPassword(ctx context.Context, userID, password string) error {
	_, err := users.Update(ctx, o.identity, userID, users.UpdateOpts{Password: password}).Extract()
	return err
}

func (o *OpenStack) Usage(ctx context.Context, projectID string) (Usage, error) {
	var u Usage
	q, err := quotasets.GetDetail(ctx, o.compute, projectID).Extract()
	if err != nil {
		return u, err
	}
	u.Instances, u.Cores, u.RAMMB = q.Instances.InUse, q.Cores.InUse, q.RAM.InUse
	page, err := floatingips.List(o.network, floatingips.ListOpts{ProjectID: projectID}).AllPages(ctx)
	if err != nil {
		return u, err
	}
	fips, err := floatingips.ExtractFloatingIPs(page)
	u.FloatingIPs = len(fips)
	return u, err
}

func (o *OpenStack) DeleteStudent(ctx context.Context, login string) error {
	p, err := o.findProject(ctx, login)
	if err != nil {
		return err
	}
	u, err := o.findUser(ctx, login)
	if err != nil {
		return err
	}
	// 학생 계정이 아닌 사용자(admin 등)는 아무것도 지우기 전에 멈춘다.
	if u != nil && (p == nil || u.DefaultProjectID != p.ID) {
		return fmt.Errorf("사용자 %s: %w", login, ErrNotStudent)
	}
	if p != nil {
		if err := o.deleteProjectResources(ctx, p.ID); err != nil {
			return err
		}
	}
	if u != nil {
		page, err := keypairs.List(o.compute, keypairs.ListOpts{UserID: u.ID}).AllPages(ctx)
		if err != nil {
			return fmt.Errorf("키페어 목록: %w", err)
		}
		kps, err := keypairs.ExtractKeyPairs(page)
		if err != nil {
			return err
		}
		for _, kp := range kps {
			if err := keypairs.Delete(ctx, o.compute, kp.Name, keypairs.DeleteOpts{UserID: u.ID}).ExtractErr(); err != nil {
				return fmt.Errorf("키페어 %s: %w", kp.Name, err)
			}
		}
		if err := users.Delete(ctx, o.identity, u.ID).ExtractErr(); err != nil {
			return fmt.Errorf("사용자 지우기: %w", err)
		}
	}
	if p != nil {
		if err := projects.Delete(ctx, o.identity, p.ID).ExtractErr(); err != nil {
			return fmt.Errorf("프로젝트 지우기: %w", err)
		}
		o.forget(p.ID)
	}
	return nil
}

// deleteProjectResources는 student.sh del과 같은 순서로 지운다: 서버 → 유동 IP → 포트 → 이미지 → 보안 그룹.
func (o *OpenStack) deleteProjectResources(ctx context.Context, projectID string) error {
	page, err := servers.List(o.compute, servers.ListOpts{AllTenants: true, TenantID: projectID}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("서버 목록: %w", err)
	}
	srvs, err := servers.ExtractServers(page)
	if err != nil {
		return err
	}
	for _, s := range srvs {
		if err := servers.Delete(ctx, o.compute, s.ID).ExtractErr(); err != nil && !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("서버 %s: %w", s.Name, err)
		}
	}
	for _, s := range srvs {
		if err := o.waitServerGone(ctx, s.ID); err != nil {
			return err
		}
	}

	page, err = floatingips.List(o.network, floatingips.ListOpts{ProjectID: projectID}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("유동 IP 목록: %w", err)
	}
	fips, err := floatingips.ExtractFloatingIPs(page)
	if err != nil {
		return err
	}
	for _, f := range fips {
		if err := floatingips.Delete(ctx, o.network, f.ID).ExtractErr(); err != nil {
			return fmt.Errorf("유동 IP %s: %w", f.FloatingIP, err)
		}
	}

	page, err = ports.List(o.network, ports.ListOpts{ProjectID: projectID}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("포트 목록: %w", err)
	}
	ps, err := ports.ExtractPorts(page)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if err := ports.Delete(ctx, o.network, p.ID).ExtractErr(); err != nil && !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("포트 %s: %w", p.ID, err)
		}
	}

	// 학생이 만든 이미지(스냅샷 등)만. 공개 이미지는 admin 프로젝트 것이라 걸리지 않는다.
	page, err = images.List(o.image, images.ListOpts{Owner: projectID}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("이미지 목록: %w", err)
	}
	imgs, err := images.ExtractImages(page)
	if err != nil {
		return err
	}
	for _, img := range imgs {
		if img.Owner != projectID {
			continue
		}
		if err := images.Delete(ctx, o.image, img.ID).ExtractErr(); err != nil {
			return fmt.Errorf("이미지 %s: %w", img.Name, err)
		}
	}

	page, err = groups.List(o.network, groups.ListOpts{ProjectID: projectID}).AllPages(ctx)
	if err != nil {
		return fmt.Errorf("보안 그룹 목록: %w", err)
	}
	sgs, err := groups.ExtractGroups(page)
	if err != nil {
		return err
	}
	for _, sg := range sgs {
		if err := groups.Delete(ctx, o.network, sg.ID).ExtractErr(); err != nil {
			return fmt.Errorf("보안 그룹 %s: %w", sg.Name, err)
		}
	}
	return nil
}

func (o *OpenStack) waitServerGone(ctx context.Context, id string) error {
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		_, err := servers.Get(ctx, o.compute, id).Extract()
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("서버 %s가 3분 안에 지워지지 않았다", id)
}

func (o *OpenStack) ListStudentProjects(ctx context.Context) ([]Project, error) {
	page, err := projects.List(o.identity, projects.ListOpts{Tags: StudentTag, DomainID: o.domainID}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := projects.ExtractProjects(page)
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(ps))
	for _, p := range ps {
		if login, ok := strings.CutPrefix(p.Name, ProjectPrefix); ok {
			out = append(out, Project{ID: p.ID, Login: login, Name: p.Description})
		}
	}
	return out, nil
}
