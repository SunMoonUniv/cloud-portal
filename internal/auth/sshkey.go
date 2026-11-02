package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

var commentRule = regexp.MustCompile(`[^A-Za-z0-9@._-]`)

// NormalizeSSHKey는 학생이 붙여 넣은 공개 키 한 줄을 검사하고, 정리한 줄과 지문(SHA256:…)을 돌려준다.
// ed25519, ECDSA, 2048비트 이상 RSA만 받는다. 옵션(command= 등)은 버린다.
func NormalizeSSHKey(in string) (line, fingerprint string, err error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", "", errors.New("공개 키를 붙여 넣는다")
	}
	if strings.Contains(in, "PRIVATE KEY") {
		return "", "", errors.New("개인 키를 넣었다. .pub로 끝나는 공개 키 파일의 내용을 넣는다")
	}
	pub, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(in))
	if err != nil {
		return "", "", errors.New("공개 키 형식이 아니다(ssh-ed25519 AAAA…처럼 시작해야 한다)")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return "", "", errors.New("공개 키는 한 줄만 넣는다")
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	case ssh.KeyAlgoRSA:
		if ck, ok := pub.(ssh.CryptoPublicKey); ok {
			if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
				return "", "", errors.New("RSA 키는 2048비트 이상이어야 한다")
			}
		}
	default:
		return "", "", errors.New("ed25519, ECDSA, RSA 키만 받는다")
	}
	line = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if c := commentRule.ReplaceAllString(comment, ""); c != "" {
		if len(c) > 64 {
			c = c[:64]
		}
		line += " " + c
	}
	return line, ssh.FingerprintSHA256(pub), nil
}

// GenerateSSHKey는 ed25519 키 쌍을 만든다. 개인 키(OpenSSH 형식)는 학생에게 한 번 내려 주고 저장하지 않는다.
func GenerateSSHKey(comment string) (private []byte, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + commentRule.ReplaceAllString(comment, "")
	return pem.EncodeToMemory(block), public, nil
}

// SSHKeyFingerprint는 저장된 공개 키의 지문이다. 읽지 못하면 빈 문자열이다.
func SSHKeyFingerprint(line string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}
