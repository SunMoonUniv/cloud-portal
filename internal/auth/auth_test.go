package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("형식이 다르다: %s", h)
	}
	if ok, err := VerifyPassword(h, "correct horse"); err != nil || !ok {
		t.Fatalf("맞는 비밀번호가 틀렸다고 나왔다: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "wrong horse"); ok {
		t.Fatal("틀린 비밀번호가 맞다고 나왔다")
	}
	h2, _ := HashPassword("correct horse")
	if h == h2 {
		t.Fatal("소금이 같다")
	}
	if _, err := VerifyPassword("$2a$10$bcrypt", "x"); err == nil {
		t.Fatal("argon2id가 아닌 해시를 받아들였다")
	}
}

func TestTempPassword(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		p := TempPassword()
		if len(p) != 12 || strings.ContainsAny(p, "0O1lI") || !ValidPassword(p) {
			t.Fatalf("임시 비밀번호가 규칙에 맞지 않다: %q", p)
		}
		if seen[p] {
			t.Fatalf("같은 임시 비밀번호가 나왔다: %q", p)
		}
		seen[p] = true
	}
}

func TestRules(t *testing.T) {
	for _, ok := range []string{"20231234", "kim.cs", "a_b-c"} {
		if !ValidLogin(ok) {
			t.Errorf("%q를 거부했다", ok)
		}
	}
	for _, bad := range []string{"", "ab", "한글", "a b", "a/b", strings.Repeat("a", 33), "x;rm"} {
		if ValidLogin(bad) {
			t.Errorf("%q를 받아들였다", bad)
		}
	}
	if !Reserved("Admin") || !Reserved("nova") || Reserved("20231234") {
		t.Error("예약된 이름 판단이 틀렸다")
	}
	if ValidPassword("1234567") || !ValidPassword("12345678") || ValidPassword(strings.Repeat("x", 129)) {
		t.Error("비밀번호 길이 규칙이 틀렸다")
	}
	if n, ok := CleanName("  홍길동 "); !ok || n != "홍길동" {
		t.Errorf("이름 정리: %q %v", n, ok)
	}
	if _, ok := CleanName("<script>"); ok {
		t.Error("꺾쇠가 든 이름을 받아들였다")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, 50*time.Millisecond)
	for i := range 3 {
		if !l.Allow("ip") {
			t.Fatalf("%d번째를 막았다", i+1)
		}
	}
	if l.Allow("ip") {
		t.Fatal("한도를 넘었는데 허용했다")
	}
	if !l.Allow("other") {
		t.Fatal("다른 키까지 막았다")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow("ip") {
		t.Fatal("시간이 지났는데도 막았다")
	}
}

func TestSSHKey(t *testing.T) {
	priv, pub, err := GenerateSSHKey("20230001@student-cloud")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(priv), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("개인 키 형식: %.40s", priv)
	}
	line, fp, err := NormalizeSSHKey("  " + pub + "\n")
	if err != nil || line != pub || !strings.HasPrefix(fp, "SHA256:") || SSHKeyFingerprint(pub) != fp {
		t.Fatalf("만든 키를 다시 읽기: %q %q %v", line, fp, err)
	}
	// 옵션은 버리고, 주석의 이상한 글자는 지운다
	line, _, err = NormalizeSSHKey(`command="rm -rf /" ` + strings.TrimSuffix(pub, " 20230001@student-cloud") + ` 나<b>`)
	if err != nil || strings.Contains(line, "command") || strings.ContainsAny(line, "<>") {
		t.Fatalf("옵션·주석 정리: %q %v", line, err)
	}
	for _, bad := range []string{"", "hello", string(priv), pub + "\n" + pub, "ssh-dss AAAAB3NzaC1kc3MAAACBAP"} {
		if _, _, err := NormalizeSSHKey(bad); err == nil {
			t.Errorf("받아들이면 안 되는 키: %.30q", bad)
		}
	}
}
