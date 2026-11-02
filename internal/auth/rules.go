package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// 아이디 규칙은 cloud-ops scripts/student.sh와 같다. 이 값이 그대로 OpenStack 사용자 이름이 된다.
var loginRule = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)

func ValidLogin(login string) bool { return loginRule.MatchString(login) }

// OpenStack 서비스 계정, 관리 계정과 겹치는 이름은 가입을 받지 않는다.
// 승인할 때도 cloud 쪽에서 학생 계정인지 다시 확인한다.
var reserved = map[string]bool{
	"admin": true, "administrator": true, "root": true, "cloud-portal": true, "cloudops": true, "eevee": true,
	"keystone": true, "glance": true, "nova": true, "neutron": true, "placement": true, "horizon": true,
	"cinder": true, "heat": true, "service": true, "openstack": true, "ubuntu": true,
}

func Reserved(login string) bool { return reserved[strings.ToLower(login)] }

const (
	MinPasswordLen = 8
	MaxPasswordLen = 128
)

func ValidPassword(pw string) bool {
	n := utf8.RuneCountInString(pw)
	return n >= MinPasswordLen && n <= MaxPasswordLen
}

// CleanName은 앞뒤 공백을 지운 이름과, 쓸 수 있는지를 돌려준다.
func CleanName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	n := utf8.RuneCountInString(name)
	return name, n >= 1 && n <= 40 && !strings.ContainsAny(name, "<>\"'\r\n")
}

// NewToken은 쿠키에 넣을 무작위 값과 DB에 넣을 그 해시를 만든다.
func NewToken() (token string, hash []byte) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token)
}

func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Limiter는 키(IP 등)별로 window 동안 max번까지만 허용한다. 프로세스 메모리에만 둔다.
type Limiter struct {
	max    int
	window time.Duration
	mu     sync.Mutex
	hits   map[string][]time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

// Allow는 한 번을 세고, 한도 안이면 true다.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.max {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)
	// 오래된 키가 쌓이지 않게 가끔 정리한다.
	if len(l.hits) > 10000 {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
	}
	return true
}
