// Package cloud는 학생 계정을 OpenStack에 만들고 고친다.
// 규칙은 cloud-ops scripts/student.sh와 같다. 한쪽을 바꾸면 다른 쪽도 같이 바꾼다.
package cloud

import (
	"context"
	"errors"
	"time"
)

const (
	ProjectPrefix = "student-" // 프로젝트 이름은 student-<아이디>
	StudentTag    = "student"  // 학생 프로젝트에만 붙는 태그. 이 태그가 없는 것은 건드리지 않는다
	MemberRole    = "member"
)

// 기본 보안 그룹은 실습실 LAN에서 오는 SSH(22)와 ping만 받는다. 유동 IP 범위(.206~.239)는 뺀다.
// 다른 학생 VM이 유동 IP로 들어오면 출발지가 그 VM의 유동 IP(또는 라우터 .206)로 보이므로 이렇게 막힌다.
var LANSources = []string{
	"192.168.0.0/25", "192.168.0.128/26", "192.168.0.192/29",
	"192.168.0.200/30", "192.168.0.204/31", "192.168.0.240/28",
}

// 학생은 공유 학생망만 쓰므로 네트워크·서브넷·라우터는 만들지 못하게 한다.
const (
	quotaNetworks      = 0
	quotaSubnets       = 0
	quotaRouters       = 0
	quotaPorts         = 10
	quotaSecGroups     = 10
	quotaSecGroupRules = 100
)

// Quota는 운영진이 학생마다 바꿀 수 있는 할당량이다.
type Quota struct {
	Instances, Cores, RAMMB, FloatingIPs int
}

var DefaultQuota = Quota{Instances: 2, Cores: 2, RAMMB: 4096, FloatingIPs: 1}

type Student struct {
	Login   string
	Name    string
	Quota   Quota
	Enabled bool
}

type Account struct {
	ProjectID string
	UserID    string
}

// Usage는 지금 쓰고 있는 양이다.
type Usage struct {
	Instances, Cores, RAMMB, FloatingIPs int
}

// Project는 OpenStack에 있는 학생 프로젝트 하나다.
type Project struct {
	ID    string
	Login string
	Name  string // 설명(학생 이름)
}

// ErrNotStudent는 같은 이름의 Keystone 사용자·프로젝트가 있지만 학생 것이 아닐 때 난다(admin, 서비스 계정 보호).
var ErrNotStudent = errors.New("같은 이름의 OpenStack 계정이 있지만 학생 계정이 아니다")

// 학생 VM은 공유 학생망, 기본 보안 그룹, 이 이미지로만 만든다(init-openstack.sh가 만든 것).
const (
	StudentNet   = "student-net"
	PublicNet    = "public"
	VMImage      = "ubuntu-24.04"
	VMUser       = "ubuntu"
	FlavorPrefix = "s." // 학생에게 보여 주는 크기(s.tiny, s.small, s.medium)
)

type Flavor struct {
	Name                 string
	VCPUs, RAMMB, DiskGB int
}

// VM은 학생 VM 하나다.
type VM struct {
	ID, Name   string
	Status     string // Nova 상태: BUILD, ACTIVE, SHUTOFF, REBOOT, ERROR …
	TaskState  string // 진행 중인 작업: powering-on, powering-off, rebooting, deleting …
	Flavor     string
	FixedIP    string
	FloatingIP string
	Fault      string // ERROR일 때 Nova가 남긴 이유
	Created    time.Time
}

type VMRequest struct {
	Name   string
	Flavor string
	SSHKey string // authorized_keys 한 줄. cloud-init으로 기본 사용자(ubuntu)에 넣는다
}

var (
	// ErrQuota는 할당량이 모자라 OpenStack이 거부한 것이다. 메시지에 OpenStack의 설명이 붙는다.
	ErrQuota = errors.New("할당량이 모자란다")
	// ErrState는 VM이 지금 상태에서 그 작업을 받지 않을 때다(이미 꺼져 있는데 끄기 등).
	ErrState = errors.New("VM이 지금 상태에서는 할 수 없다")
)

// VMs는 학생 프로젝트 안에서 VM을 다룬다. 포털 계정이 그 프로젝트의 member로 움직이므로
// 할당량은 OpenStack이 지키고, 다른 프로젝트의 VM은 보이지 않는다.
type VMs interface {
	Flavors(ctx context.Context) ([]Flavor, error)
	ListVMs(ctx context.Context, projectID string) ([]VM, error)
	CreateVM(ctx context.Context, projectID string, r VMRequest) (VM, error)
	// VMAction은 start, stop, reboot 중 하나다.
	VMAction(ctx context.Context, projectID, vmID, action string) error
	// DeleteVM은 VM에 붙은 유동 IP를 돌려준 뒤 VM을 지운다.
	DeleteVM(ctx context.Context, projectID, vmID string) error
	// WaitActive는 VM이 켜질 때까지 기다린다(ERROR가 되면 오류).
	WaitActive(ctx context.Context, projectID, vmID string) error
	AttachFloatingIP(ctx context.Context, projectID, vmID string) (string, error)
	DetachFloatingIP(ctx context.Context, projectID, vmID string) error
}

type Cloud interface {
	VMs
	// EnsureStudent는 프로젝트·사용자·역할·할당량·기본 보안 그룹 규칙을 맞추고, 사용자를 켜거나 끈다.
	// 몇 번을 불러도 결과가 같다. 비밀번호는 건드리지 않는다.
	EnsureStudent(ctx context.Context, s Student) (Account, error)
	SetEnabled(ctx context.Context, userID string, enabled bool) error
	SetPassword(ctx context.Context, userID, password string) error
	Usage(ctx context.Context, projectID string) (Usage, error)
	// DeleteStudent는 VM·유동 IP·포트·이미지·보안 그룹·키페어를 지우고 사용자와 프로젝트를 없앤다.
	DeleteStudent(ctx context.Context, login string) error
	ListStudentProjects(ctx context.Context) ([]Project, error)
}
