-- 포털 DB. 학생·운영진 계정의 기준 정보이고, OpenStack은 이 내용에 맞춘다(internal/reconcile).
-- 시각은 모두 유닉스 초다.

CREATE TABLE users (
    id                    INTEGER PRIMARY KEY,
    login                 TEXT    NOT NULL UNIQUE,      -- 학번 등. OpenStack 사용자 이름과 같다
    name                  TEXT    NOT NULL,
    password_hash         TEXT    NOT NULL,             -- argon2id
    role                  TEXT    NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
    status                TEXT    NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'active', 'suspended', 'expired', 'rejected')),
    expires_at            INTEGER,                      -- 없으면 기한 없음
    quota_instances       INTEGER NOT NULL DEFAULT 2,
    quota_cores           INTEGER NOT NULL DEFAULT 2,
    quota_ram_mb          INTEGER NOT NULL DEFAULT 4096,
    quota_floating_ips    INTEGER NOT NULL DEFAULT 1,
    must_change_password  INTEGER NOT NULL DEFAULT 0,   -- 임시 비밀번호로 들어오면 먼저 바꾸게 한다
    cloud_password_synced INTEGER NOT NULL DEFAULT 0,   -- Keystone 비밀번호를 포털 비밀번호와 맞췄는지
    cloud_project_id      TEXT    NOT NULL DEFAULT '',
    cloud_user_id         TEXT    NOT NULL DEFAULT '',
    synced_at             INTEGER,                      -- 마지막으로 OpenStack에 맞춘 시각
    sync_error            TEXT    NOT NULL DEFAULT '',
    signup_ip             TEXT    NOT NULL DEFAULT '',
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB    PRIMARY KEY,                     -- 쿠키 값의 SHA-256
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE audit (
    id     INTEGER PRIMARY KEY,
    at     INTEGER NOT NULL,
    actor  TEXT    NOT NULL,                            -- 운영진 아이디, 학생 아이디 또는 system
    action TEXT    NOT NULL,
    target TEXT    NOT NULL DEFAULT '',
    detail TEXT    NOT NULL DEFAULT ''
);
