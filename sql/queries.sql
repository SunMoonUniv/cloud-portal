-- name: CreateUser :one
INSERT INTO users (login, name, password_hash, role, status, signup_ip, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByLogin :one
SELECT * FROM users WHERE login = ?;

-- name: CountByStatus :one
SELECT count(*) FROM users WHERE role = 'student' AND status = ?;

-- name: ListStudents :many
SELECT * FROM users WHERE role = 'student' ORDER BY login;

-- name: ListStudentsByStatus :many
SELECT * FROM users WHERE role = 'student' AND status = ? ORDER BY created_at, login;

-- name: ListCloudManaged :many
SELECT * FROM users
WHERE role = 'student' AND status IN ('active', 'suspended', 'expired')
ORDER BY login;

-- name: SetStatus :exec
UPDATE users SET status = ?, updated_at = ? WHERE id = ?;

-- name: ExpireDue :many
UPDATE users SET status = 'expired', updated_at = sqlc.arg(now)
WHERE role = 'student' AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= sqlc.arg(now)
RETURNING login;

-- name: SetExpiry :exec
UPDATE users SET expires_at = ?, updated_at = ? WHERE id = ?;

-- name: SetQuota :exec
UPDATE users
SET quota_instances = ?, quota_cores = ?, quota_ram_mb = ?, quota_floating_ips = ?, updated_at = ?
WHERE id = ?;

-- name: SetPassword :exec
UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?;

-- name: SetCloudPasswordSynced :exec
UPDATE users SET cloud_password_synced = ?, updated_at = ? WHERE id = ?;

-- name: SetCloudIDs :exec
UPDATE users SET cloud_project_id = ?, cloud_user_id = ?, updated_at = ? WHERE id = ?;

-- name: SetSyncResult :exec
UPDATE users SET synced_at = ?, sync_error = ? WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;

-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?);

-- name: GetSessionUser :one
SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id
WHERE sessions.token_hash = ? AND sessions.expires_at > ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE token_hash = ?;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= ?;

-- name: AddAudit :exec
INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?);

-- name: ListAudit :many
SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?;

-- name: SetSSHKey :exec
UPDATE users SET ssh_public_key = ?, updated_at = ? WHERE id = ?;
