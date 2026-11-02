package cloud

import (
	"context"
	"sync"
)

// Lazy는 처음 쓸 때 OpenStack에 접속한다. 부팅 직후처럼 Keystone이 아직 뜨지 않았어도 포털은 먼저 뜨고,
// 가입·로그인 화면은 그대로 쓸 수 있다. 접속에 실패하면 다음에 다시 시도한다.
type Lazy struct {
	mu sync.Mutex
	c  *OpenStack
}

func (l *Lazy) get(ctx context.Context) (*OpenStack, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c != nil {
		return l.c, nil
	}
	c, err := NewOpenStack(ctx)
	if err != nil {
		return nil, err
	}
	l.c = c
	return c, nil
}

func (l *Lazy) EnsureStudent(ctx context.Context, s Student) (Account, error) {
	c, err := l.get(ctx)
	if err != nil {
		return Account{}, err
	}
	return c.EnsureStudent(ctx, s)
}

func (l *Lazy) SetEnabled(ctx context.Context, userID string, enabled bool) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.SetEnabled(ctx, userID, enabled)
}

func (l *Lazy) SetPassword(ctx context.Context, userID, password string) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.SetPassword(ctx, userID, password)
}

func (l *Lazy) Usage(ctx context.Context, projectID string) (Usage, error) {
	c, err := l.get(ctx)
	if err != nil {
		return Usage{}, err
	}
	return c.Usage(ctx, projectID)
}

func (l *Lazy) DeleteStudent(ctx context.Context, login string) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.DeleteStudent(ctx, login)
}

func (l *Lazy) ListStudentProjects(ctx context.Context) ([]Project, error) {
	c, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return c.ListStudentProjects(ctx)
}

func (l *Lazy) Flavors(ctx context.Context) ([]Flavor, error) {
	c, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return c.Flavors(ctx)
}

func (l *Lazy) ListVMs(ctx context.Context, projectID string) ([]VM, error) {
	c, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return c.ListVMs(ctx, projectID)
}

func (l *Lazy) CreateVM(ctx context.Context, projectID string, r VMRequest) (VM, error) {
	c, err := l.get(ctx)
	if err != nil {
		return VM{}, err
	}
	return c.CreateVM(ctx, projectID, r)
}

func (l *Lazy) VMAction(ctx context.Context, projectID, vmID, action string) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.VMAction(ctx, projectID, vmID, action)
}

func (l *Lazy) DeleteVM(ctx context.Context, projectID, vmID string) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.DeleteVM(ctx, projectID, vmID)
}

func (l *Lazy) WaitActive(ctx context.Context, projectID, vmID string) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.WaitActive(ctx, projectID, vmID)
}

func (l *Lazy) AttachFloatingIP(ctx context.Context, projectID, vmID string) (string, error) {
	c, err := l.get(ctx)
	if err != nil {
		return "", err
	}
	return c.AttachFloatingIP(ctx, projectID, vmID)
}

func (l *Lazy) DetachFloatingIP(ctx context.Context, projectID, vmID string) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.DetachFloatingIP(ctx, projectID, vmID)
}
