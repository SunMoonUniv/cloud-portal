// Package store는 포털 DB(SQLite)를 연다. 쿼리는 sqlc가 만든 db 패키지에 있다.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"cloud-portal/internal/store/db"
	sqlschema "cloud-portal/sql"
)

// 스키마를 바꾸면 migrations에 한 단계를 더하고 schemaVersion을 올린다.
const schemaVersion = 2

var migrations = []string{
	1: sqlschema.Schema,
	2: sqlschema.SSHKey,
}

type Store struct {
	*db.Queries
	DB *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// 쓰기는 하나씩만 된다. 연결을 하나로 두면 SQLITE_BUSY를 볼 일이 없다.
	conn.SetMaxOpenConns(1)
	if err := migrate(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return &Store{Queries: db.New(conn), DB: conn}, nil
}

func migrate(conn *sql.DB) error {
	var version int
	if err := conn.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("DB 스키마 %d은 이 프로그램(%d)보다 새롭다", version, schemaVersion)
	}
	for v := version + 1; v <= schemaVersion; v++ {
		tx, err := conn.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("스키마 %d: %w", v, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.DB.Close() }

// Audit은 감사 로그에 한 줄을 남긴다. 실패해도 하던 일은 멈추지 않는다.
func (s *Store) Audit(ctx context.Context, actor, action, target, detail string) {
	_ = s.AddAudit(ctx, db.AddAuditParams{
		At: time.Now().Unix(), Actor: actor, Action: action, Target: target, Detail: detail,
	})
}
