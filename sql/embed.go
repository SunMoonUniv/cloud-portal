// Package sqlschema는 DB 스키마를 프로그램에 넣는다. 쿼리 코드는 sqlc가 internal/store/db에 만든다.
package sqlschema

import _ "embed"

//go:embed schema.sql
var Schema string

//go:embed 002_ssh_key.sql
var SSHKey string
