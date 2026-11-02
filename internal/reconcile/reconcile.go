// Package reconcile은 포털 DB를 기준으로 OpenStack 학생 계정을 맞춘다.
package reconcile

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"cloud-portal/internal/cloud"
	"cloud-portal/internal/store"
	"cloud-portal/internal/store/db"
)

type Reconciler struct {
	Store    *store.Store
	Cloud    cloud.Cloud
	Log      *slog.Logger
	Interval time.Duration
	mu       sync.Mutex // 한 번에 하나씩만 돈다
}

// Run은 Interval마다 Once를 돌린다. ctx가 끝나면 멈춘다.
func (r *Reconciler) Run(ctx context.Context) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if err := r.Once(ctx); err != nil {
			r.Log.Warn("되맞추기", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once는 만료일이 지난 계정을 expired로 바꾸고, OpenStack에 맞춰야 할 계정을 모두 한 번씩 맞춘다.
func (r *Reconciler) Once(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().Unix()
	expired, err := r.Store.ExpireDue(ctx, now)
	if err != nil {
		return err
	}
	for _, login := range expired {
		r.Store.Audit(ctx, "system", "만료", login, "만료일이 지났다")
	}
	if err := r.Store.DeleteExpiredSessions(ctx, now); err != nil {
		return err
	}
	users, err := r.Store.ListCloudManaged(ctx)
	if err != nil {
		return err
	}
	failed := 0
	for _, u := range users {
		if err := r.sync(ctx, u); err != nil {
			failed++
		}
	}
	r.Log.Info("되맞추기 끝", "accounts", len(users), "failed", failed, "expired", len(expired))
	return nil
}

// SyncLogin은 한 계정만 바로 맞추고, 맞춘 뒤의 DB 내용을 돌려준다. 운영진 작업 직후에 부른다.
func (r *Reconciler) SyncLogin(ctx context.Context, login string) (db.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, err := r.Store.GetUserByLogin(ctx, login)
	if err != nil {
		return u, err
	}
	syncErr := r.sync(ctx, u)
	if u, err = r.Store.GetUserByLogin(ctx, login); err != nil {
		return u, err
	}
	return u, syncErr
}

func (r *Reconciler) sync(ctx context.Context, u db.User) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var err error
	switch u.Status {
	case "active":
		var acct cloud.Account
		acct, err = r.Cloud.EnsureStudent(ctx, cloud.Student{
			Login: u.Login, Name: u.Name, Enabled: true,
			Quota: cloud.Quota{
				Instances: int(u.QuotaInstances), Cores: int(u.QuotaCores),
				RAMMB: int(u.QuotaRamMb), FloatingIPs: int(u.QuotaFloatingIps),
			},
		})
		if err == nil && (acct.ProjectID != u.CloudProjectID || acct.UserID != u.CloudUserID) {
			err = r.Store.SetCloudIDs(ctx, db.SetCloudIDsParams{
				CloudProjectID: acct.ProjectID, CloudUserID: acct.UserID, UpdatedAt: time.Now().Unix(), ID: u.ID,
			})
		}
	case "suspended", "expired":
		// 로그인만 막는다. VM은 그대로 둔다(2026-11-01 결정).
		if u.CloudUserID != "" {
			err = r.Cloud.SetEnabled(ctx, u.CloudUserID, false)
		}
	default:
		return nil
	}
	msg := ""
	if err != nil {
		msg = err.Error()
		r.Log.Warn("계정 맞추기 실패", "login", u.Login, "status", u.Status, "err", err)
	}
	if e := r.Store.SetSyncResult(ctx, db.SetSyncResultParams{
		SyncedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true}, SyncError: msg, ID: u.ID,
	}); e != nil && err == nil {
		err = e
	}
	return err
}
