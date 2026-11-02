package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
)

// projectClients는 학생 프로젝트 하나에 범위를 둔 클라이언트다(포털 계정이 그 프로젝트의 member).
type projectClients struct {
	compute, network *gophercloud.ServiceClient
}

// forProject는 프로젝트별 클라이언트를 만들어 두고 다시 쓴다. 토큰이 만료되면 gophercloud가 다시 받는다.
func (o *OpenStack) forProject(ctx context.Context, projectID string) (*projectClients, error) {
	o.pmu.Lock()
	defer o.pmu.Unlock()
	if pc, ok := o.projects[projectID]; ok {
		return pc, nil
	}
	opts := o.auth
	opts.TenantID = projectID
	provider, err := openstack.AuthenticatedClient(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("학생 프로젝트로 로그인: %w", err)
	}
	provider.HTTPClient = http.Client{Timeout: 60 * time.Second}
	pc := &projectClients{}
	if pc.compute, err = openstack.NewComputeV2(provider, o.eo); err != nil {
		return nil, err
	}
	// 2.47부터 VM 목록에 플레이버 이름(original_name)이 들어 있다.
	pc.compute.Microversion = "2.47"
	if pc.network, err = openstack.NewNetworkV2(provider, o.eo); err != nil {
		return nil, err
	}
	o.projects[projectID] = pc
	return pc, nil
}

// forget은 프로젝트를 지운 뒤 캐시에서 뺀다.
func (o *OpenStack) forget(projectID string) {
	o.pmu.Lock()
	delete(o.projects, projectID)
	o.pmu.Unlock()
}

func (o *OpenStack) networkID(ctx context.Context, name string) (string, error) {
	page, err := networks.List(o.network, networks.ListOpts{Name: name}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("네트워크 %s: %w", name, err)
	}
	ns, err := networks.ExtractNetworks(page)
	if err != nil || len(ns) != 1 {
		return "", fmt.Errorf("네트워크 %s를 하나로 찾지 못했다(init-openstack.sh를 돌렸는지 본다)", name)
	}
	return ns[0].ID, nil
}

// apiErr는 OpenStack이 할당량이나 상태 때문에 거부한 것을 ErrQuota·ErrState로 바꾼다.
func apiErr(err error) error {
	if err == nil {
		return nil
	}
	var ue gophercloud.ErrUnexpectedResponseCode
	if errors.As(err, &ue) {
		body := string(ue.Body)
		switch {
		case strings.Contains(body, "Quota exceeded") || strings.Contains(body, "OverQuota"):
			return fmt.Errorf("%w: %s", ErrQuota, firstMessage(body))
		case ue.Actual == http.StatusConflict:
			return fmt.Errorf("%w: %s", ErrState, firstMessage(body))
		}
	}
	return err
}

// firstMessage는 OpenStack 오류 본문에서 "message" 값을 꺼낸다.
func firstMessage(body string) string {
	if i := strings.Index(body, `"message": "`); i >= 0 {
		rest := body[i+len(`"message": "`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			return rest[:j]
		}
	}
	if len(body) > 200 {
		return body[:200]
	}
	return body
}

func (o *OpenStack) Flavors(ctx context.Context) ([]Flavor, error) {
	page, err := flavors.ListDetail(o.compute, flavors.ListOpts{AccessType: flavors.PublicAccess}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	fs, err := flavors.ExtractFlavors(page)
	if err != nil {
		return nil, err
	}
	var out []Flavor
	for _, f := range fs {
		if strings.HasPrefix(f.Name, FlavorPrefix) {
			out = append(out, Flavor{Name: f.Name, VCPUs: f.VCPUs, RAMMB: f.RAM, DiskGB: f.Disk})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RAMMB < out[j].RAMMB })
	return out, nil
}

func (o *OpenStack) flavorID(ctx context.Context, name string) (string, error) {
	page, err := flavors.ListDetail(o.compute, flavors.ListOpts{AccessType: flavors.PublicAccess}).AllPages(ctx)
	if err != nil {
		return "", err
	}
	fs, err := flavors.ExtractFlavors(page)
	if err != nil {
		return "", err
	}
	for _, f := range fs {
		if f.Name == name && strings.HasPrefix(name, FlavorPrefix) {
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("크기 %s가 없다", name)
}

func (o *OpenStack) imageID(ctx context.Context) (string, error) {
	page, err := images.List(o.image, images.ListOpts{Name: VMImage}).AllPages(ctx)
	if err != nil {
		return "", err
	}
	imgs, err := images.ExtractImages(page)
	if err != nil {
		return "", err
	}
	for _, img := range imgs {
		if img.Status == images.ImageStatusActive {
			return img.ID, nil
		}
	}
	return "", fmt.Errorf("이미지 %s가 없다", VMImage)
}

func toVM(s servers.Server) VM {
	vm := VM{ID: s.ID, Name: s.Name, Status: s.Status, TaskState: s.TaskState, Created: s.Created, Fault: s.Fault.Message}
	if n, ok := s.Flavor["original_name"].(string); ok {
		vm.Flavor = n
	}
	for _, addrs := range s.Addresses {
		list, _ := addrs.([]any)
		for _, a := range list {
			m, _ := a.(map[string]any)
			addr, _ := m["addr"].(string)
			switch m["OS-EXT-IPS:type"] {
			case "floating":
				vm.FloatingIP = addr
			case "fixed":
				if vm.FixedIP == "" {
					vm.FixedIP = addr
				}
			}
		}
	}
	return vm
}

func (o *OpenStack) ListVMs(ctx context.Context, projectID string) ([]VM, error) {
	pc, err := o.forProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	page, err := servers.List(pc.compute, servers.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	ss, err := servers.ExtractServers(page)
	if err != nil {
		return nil, err
	}
	// 유동 IP는 Neutron에서 직접 읽는다. Nova의 주소 정보는 붙이고 뗀 뒤 몇 초 늦게 바뀐다.
	page, err = floatingips.List(pc.network, floatingips.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, err
	}
	fips, err := floatingips.ExtractFloatingIPs(page)
	if err != nil {
		return nil, err
	}
	byFixed := map[string]string{}
	for _, f := range fips {
		if f.PortID != "" {
			byFixed[f.FixedIP] = f.FloatingIP
		}
	}
	out := make([]VM, 0, len(ss))
	for _, s := range ss {
		vm := toVM(s)
		vm.FloatingIP = byFixed[vm.FixedIP]
		out = append(out, vm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// cloudConfig는 학생 공개 키를 기본 사용자에 넣는 cloud-init 설정이다.
func cloudConfig(sshKey string) []byte {
	return []byte("#cloud-config\nssh_authorized_keys:\n  - " + strings.TrimSpace(sshKey) + "\n")
}

func (o *OpenStack) CreateVM(ctx context.Context, projectID string, r VMRequest) (VM, error) {
	pc, err := o.forProject(ctx, projectID)
	if err != nil {
		return VM{}, err
	}
	flavor, err := o.flavorID(ctx, r.Flavor)
	if err != nil {
		return VM{}, err
	}
	image, err := o.imageID(ctx)
	if err != nil {
		return VM{}, err
	}
	s, err := servers.Create(ctx, pc.compute, servers.CreateOpts{
		Name: r.Name, FlavorRef: flavor, ImageRef: image,
		Networks:       []servers.Network{{UUID: o.studentNetID}},
		SecurityGroups: []string{"default"},
		UserData:       cloudConfig(r.SSHKey),
		Metadata:       map[string]string{"created_by": "cloud-portal"},
	}, nil).Extract()
	if err != nil {
		return VM{}, apiErr(err)
	}
	return VM{ID: s.ID, Name: r.Name, Status: "BUILD", Flavor: r.Flavor}, nil
}

func (o *OpenStack) VMAction(ctx context.Context, projectID, vmID, action string) error {
	pc, err := o.forProject(ctx, projectID)
	if err != nil {
		return err
	}
	switch action {
	case "start":
		err = servers.Start(ctx, pc.compute, vmID).ExtractErr()
	case "stop":
		err = servers.Stop(ctx, pc.compute, vmID).ExtractErr()
	case "reboot":
		err = servers.Reboot(ctx, pc.compute, vmID, servers.RebootOpts{Type: servers.SoftReboot}).ExtractErr()
	default:
		return fmt.Errorf("모르는 작업: %s", action)
	}
	return apiErr(err)
}

// serverFloatingIPs는 VM의 포트에 붙은 유동 IP를 모두 돌려준다.
func (o *OpenStack) serverFloatingIPs(ctx context.Context, pc *projectClients, vmID string) ([]ports.Port, []floatingips.FloatingIP, error) {
	page, err := ports.List(pc.network, ports.ListOpts{DeviceID: vmID}).AllPages(ctx)
	if err != nil {
		return nil, nil, err
	}
	ps, err := ports.ExtractPorts(page)
	if err != nil {
		return nil, nil, err
	}
	var fips []floatingips.FloatingIP
	for _, p := range ps {
		page, err := floatingips.List(pc.network, floatingips.ListOpts{PortID: p.ID}).AllPages(ctx)
		if err != nil {
			return nil, nil, err
		}
		fs, err := floatingips.ExtractFloatingIPs(page)
		if err != nil {
			return nil, nil, err
		}
		fips = append(fips, fs...)
	}
	return ps, fips, nil
}

func (o *OpenStack) DeleteVM(ctx context.Context, projectID, vmID string) error {
	pc, err := o.forProject(ctx, projectID)
	if err != nil {
		return err
	}
	if err := o.DetachFloatingIP(ctx, projectID, vmID); err != nil {
		return err
	}
	err = servers.Delete(ctx, pc.compute, vmID).ExtractErr()
	if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
		return nil
	}
	return apiErr(err)
}

func (o *OpenStack) WaitActive(ctx context.Context, projectID, vmID string) error {
	pc, err := o.forProject(ctx, projectID)
	if err != nil {
		return err
	}
	for {
		s, err := servers.Get(ctx, pc.compute, vmID).Extract()
		if err != nil {
			return err
		}
		switch s.Status {
		case "ACTIVE":
			return nil
		case "ERROR":
			return fmt.Errorf("VM을 만들지 못했다: %s", s.Fault.Message)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (o *OpenStack) AttachFloatingIP(ctx context.Context, projectID, vmID string) (string, error) {
	pc, err := o.forProject(ctx, projectID)
	if err != nil {
		return "", err
	}
	ps, fips, err := o.serverFloatingIPs(ctx, pc, vmID)
	if err != nil {
		return "", err
	}
	if len(fips) > 0 {
		return fips[0].FloatingIP, nil
	}
	if len(ps) == 0 {
		return "", fmt.Errorf("%w: VM에 네트워크 포트가 아직 없다", ErrState)
	}
	f, err := floatingips.Create(ctx, pc.network, floatingips.CreateOpts{
		FloatingNetworkID: o.publicNetID, PortID: ps[0].ID,
	}).Extract()
	if err != nil {
		return "", apiErr(err)
	}
	return f.FloatingIP, nil
}

// DetachFloatingIP는 VM의 유동 IP를 떼고 돌려준다(다른 VM에 붙일 수 있게).
func (o *OpenStack) DetachFloatingIP(ctx context.Context, projectID, vmID string) error {
	pc, err := o.forProject(ctx, projectID)
	if err != nil {
		return err
	}
	_, fips, err := o.serverFloatingIPs(ctx, pc, vmID)
	if err != nil {
		return err
	}
	for _, f := range fips {
		if err := floatingips.Delete(ctx, pc.network, f.ID).ExtractErr(); err != nil && !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("유동 IP %s: %w", f.FloatingIP, err)
		}
	}
	return nil
}
