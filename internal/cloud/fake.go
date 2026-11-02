package cloud

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
)

// Fake는 OpenStack 없이 포털을 돌리거나 시험할 때 쓴다(PORTAL_CLOUD=fake). 메모리에만 둔다.
type Fake struct {
	mu       sync.Mutex
	seq      int
	Accounts map[string]*FakeAccount // 아이디 → 계정
	// Fail이 있으면 다음 EnsureStudent가 이 오류를 낸다(시험용).
	Fail error
}

type FakeAccount struct {
	Account
	Name     string
	Quota    Quota
	Enabled  bool
	Password string
	VMs      []*FakeVM
}

type FakeVM struct {
	VM
	SSHKey string
}

// FakeFlavors는 init-openstack.sh의 크기와 같다.
var FakeFlavors = []Flavor{
	{Name: "s.tiny", VCPUs: 1, RAMMB: 512, DiskGB: 10},
	{Name: "s.small", VCPUs: 2, RAMMB: 2048, DiskGB: 30},
	{Name: "s.medium", VCPUs: 2, RAMMB: 4096, DiskGB: 50},
}

func NewFake() *Fake { return &Fake{Accounts: map[string]*FakeAccount{}} }

func (f *Fake) EnsureStudent(_ context.Context, s Student) (Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		err := f.Fail
		f.Fail = nil
		return Account{}, err
	}
	a, ok := f.Accounts[s.Login]
	if !ok {
		f.seq++
		a = &FakeAccount{Account: Account{
			ProjectID: fmt.Sprintf("project-%d", f.seq), UserID: fmt.Sprintf("user-%d", f.seq),
		}}
		f.Accounts[s.Login] = a
	}
	a.Name, a.Quota, a.Enabled = s.Name, s.Quota, s.Enabled
	return a.Account, nil
}

func (f *Fake) byUser(userID string) (*FakeAccount, error) {
	for _, a := range f.Accounts {
		if a.UserID == userID {
			return a, nil
		}
	}
	return nil, fmt.Errorf("사용자 %s가 없다", userID)
}

func (f *Fake) SetEnabled(_ context.Context, userID string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := f.byUser(userID)
	if err == nil {
		a.Enabled = enabled
	}
	return err
}

func (f *Fake) SetPassword(_ context.Context, userID, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := f.byUser(userID)
	if err == nil {
		a.Password = password
	}
	return err
}

func (f *Fake) byProject(projectID string) (*FakeAccount, error) {
	for _, a := range f.Accounts {
		if a.ProjectID == projectID {
			return a, nil
		}
	}
	return nil, fmt.Errorf("프로젝트 %s가 없다", projectID)
}

func fakeFlavor(name string) (Flavor, bool) {
	for _, fl := range FakeFlavors {
		if fl.Name == name {
			return fl, true
		}
	}
	return Flavor{}, false
}

func (a *FakeAccount) usage() Usage {
	var u Usage
	for _, vm := range a.VMs {
		fl, _ := fakeFlavor(vm.Flavor)
		u.Instances++
		u.Cores += fl.VCPUs
		u.RAMMB += fl.RAMMB
		if vm.FloatingIP != "" {
			u.FloatingIPs++
		}
	}
	return u
}

func (f *Fake) Usage(_ context.Context, projectID string) (Usage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := f.byProject(projectID)
	if err != nil {
		return Usage{}, err
	}
	return a.usage(), nil
}

func (f *Fake) Flavors(context.Context) ([]Flavor, error) { return FakeFlavors, nil }

func (f *Fake) ListVMs(_ context.Context, projectID string) ([]VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := f.byProject(projectID)
	if err != nil {
		return nil, err
	}
	out := make([]VM, 0, len(a.VMs))
	for _, vm := range a.VMs {
		out = append(out, vm.VM)
	}
	return out, nil
}

// CreateVM은 바로 켜진 VM을 만든다. 할당량은 OpenStack처럼 검사한다.
func (f *Fake) CreateVM(_ context.Context, projectID string, r VMRequest) (VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, err := f.byProject(projectID)
	if err != nil {
		return VM{}, err
	}
	fl, ok := fakeFlavor(r.Flavor)
	if !ok {
		return VM{}, fmt.Errorf("크기 %s가 없다", r.Flavor)
	}
	u := a.usage()
	if u.Instances+1 > a.Quota.Instances || u.Cores+fl.VCPUs > a.Quota.Cores || u.RAMMB+fl.RAMMB > a.Quota.RAMMB {
		return VM{}, fmt.Errorf("%w: Quota exceeded for cores, ram", ErrQuota)
	}
	f.seq++
	vm := &FakeVM{VM: VM{
		ID: fmt.Sprintf("vm-%d", f.seq), Name: r.Name, Status: "ACTIVE", Flavor: r.Flavor,
		FixedIP: fmt.Sprintf("10.10.0.%d", 10+f.seq), Created: time.Now(),
	}, SSHKey: r.SSHKey}
	a.VMs = append(a.VMs, vm)
	return vm.VM, nil
}

func (f *Fake) vm(projectID, vmID string) (*FakeAccount, *FakeVM, error) {
	a, err := f.byProject(projectID)
	if err != nil {
		return nil, nil, err
	}
	for _, vm := range a.VMs {
		if vm.ID == vmID {
			return a, vm, nil
		}
	}
	return nil, nil, fmt.Errorf("VM %s가 없다", vmID)
}

func (f *Fake) VMAction(_ context.Context, projectID, vmID, action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, vm, err := f.vm(projectID, vmID)
	if err != nil {
		return err
	}
	switch {
	case action == "start" && vm.Status == "SHUTOFF":
		vm.Status = "ACTIVE"
	case action == "stop" && vm.Status == "ACTIVE":
		vm.Status = "SHUTOFF"
	case action == "reboot" && vm.Status == "ACTIVE":
	default:
		return fmt.Errorf("%w: %s %s", ErrState, vm.Status, action)
	}
	return nil
}

func (f *Fake) DeleteVM(_ context.Context, projectID, vmID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, vm, err := f.vm(projectID, vmID)
	if err != nil {
		return err
	}
	a.VMs = slices.DeleteFunc(a.VMs, func(x *FakeVM) bool { return x == vm })
	return nil
}

func (f *Fake) WaitActive(context.Context, string, string) error { return nil }

func (f *Fake) AttachFloatingIP(_ context.Context, projectID, vmID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, vm, err := f.vm(projectID, vmID)
	if err != nil {
		return "", err
	}
	if vm.FloatingIP != "" {
		return vm.FloatingIP, nil
	}
	if a.usage().FloatingIPs >= a.Quota.FloatingIPs {
		return "", fmt.Errorf("%w: Quota exceeded for resources: ['floatingip']", ErrQuota)
	}
	f.seq++
	vm.FloatingIP = fmt.Sprintf("192.168.0.%d", 206+f.seq%30)
	return vm.FloatingIP, nil
}

func (f *Fake) DetachFloatingIP(_ context.Context, projectID, vmID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, vm, err := f.vm(projectID, vmID)
	if err == nil {
		vm.FloatingIP = ""
	}
	return err
}

func (f *Fake) DeleteStudent(_ context.Context, login string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Accounts, login)
	return nil
}

func (f *Fake) ListStudentProjects(context.Context) ([]Project, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Project
	for login, a := range f.Accounts {
		out = append(out, Project{ID: a.ProjectID, Login: login, Name: a.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Login < out[j].Login })
	return out, nil
}

// Get은 시험에서 계정 상태를 볼 때 쓴다.
func (f *Fake) Get(login string) (FakeAccount, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.Accounts[login]
	if !ok {
		return FakeAccount{}, false
	}
	return *a, true
}

// VMList는 시험에서 VM과 넣은 키를 볼 때 쓴다(복사본).
func (f *Fake) VMList(login string) []FakeVM {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.Accounts[login]
	if !ok {
		return nil
	}
	out := make([]FakeVM, 0, len(a.VMs))
	for _, vm := range a.VMs {
		out = append(out, *vm)
	}
	return out
}
