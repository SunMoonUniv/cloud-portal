// Package auth는 비밀번호 해시, 입력 규칙, 세션 토큰, 횟수 제한을 맡는다.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id 값. node01은 메모리가 빠듯하므로 OWASP 최소 권장값(19MiB, 2회)을 쓴다.
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

var b64 = base64.RawStdEncoding

// HashPassword는 PHC 형식($argon2id$v=19$m=…,t=…,p=…$소금$해시)으로 돌려준다.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword는 해시에 적힌 값으로 다시 계산해 비교한다.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("argon2id 해시가 아니다")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("argon2 버전이 맞지 않는다")
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("argon2 값: %w", err)
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// 임시 비밀번호에는 헷갈리는 글자(0 O 1 l I)를 쓰지 않는다.
const tempAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func TempPassword() string {
	// 글자마다 고르게 나오도록 알파벳 길이의 배수를 넘는 바이트는 버린다.
	limit := byte(256 - 256%len(tempAlphabet))
	out := make([]byte, 0, 12)
	buf := make([]byte, 32)
	for len(out) < cap(out) {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		for _, b := range buf {
			if b < limit && len(out) < cap(out) {
				out = append(out, tempAlphabet[int(b)%len(tempAlphabet)])
			}
		}
	}
	return string(out)
}
