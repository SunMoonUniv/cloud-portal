package web

import (
	"bufio"
	"context"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"cloud-portal/internal/auth"
	"cloud-portal/internal/cloud"
	"cloud-portal/internal/reconcile"
	"cloud-portal/internal/store"
	"cloud-portal/internal/store/db"
)

type env struct {
	t    *testing.T
	ts   *httptest.Server
	st   *store.Store
	fake *cloud.Fake
	rec  *reconcile.Reconciler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "portal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fake := cloud.NewFake()
	rec := &reconcile.Reconciler{Store: st, Cloud: fake, Log: log, Interval: time.Hour}
	srv, err := New(Config{ConsoleURL: "http://console", PendingMax: 3, SignupPerHour: 4, SessionTTL: time.Hour}, st, fake, rec, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, ts: ts, st: st, fake: fake, rec: rec}
}

func (e *env) addAdmin(login, pw string) {
	e.t.Helper()
	hash, _ := auth.HashPassword(pw)
	now := time.Now().Unix()
	if _, err := e.st.CreateUser(context.Background(), db.CreateUserParams{
		Login: login, Name: "운영자", PasswordHash: hash, Role: "admin", Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) user(login string) db.User {
	e.t.Helper()
	u, err := e.st.GetUserByLogin(context.Background(), login)
	if err != nil {
		e.t.Fatalf("%s: %v", login, err)
	}
	return u
}

// browser는 쿠키를 들고 다니는 사용자 하나다.
type browser struct {
	e *env
	c *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{e: e, c: &http.Client{Jar: jar}}
}

func (b *browser) get(path string) (int, string, string) {
	b.e.t.Helper()
	resp, err := b.c.Get(b.e.ts.URL + path)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Request.URL.Path, string(body)
}

func (b *browser) csrf() string {
	u, _ := url.Parse(b.e.ts.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == "csrf" {
			return c.Value
		}
	}
	b.get("/login")
	return b.csrf()
}

// post는 폼을 보내고 (상태, 리다이렉트 뒤 최종 경로, 본문)을 돌려준다.
func (b *browser) post(path string, form url.Values) (int, string, string) {
	b.e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if form.Get("csrf") == "" {
		form.Set("csrf", b.csrf())
	}
	resp, err := b.c.PostForm(b.e.ts.URL+path, form)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Request.URL.Path, string(body)
}

func (b *browser) login(login, pw string) (int, string, string) {
	return b.post("/login", url.Values{"login": {login}, "password": {pw}})
}

func signupForm(login, name, pw string) url.Values {
	return url.Values{"login": {login}, "name": {name}, "password": {pw}, "password2": {pw}}
}

func TestStudentLifecycle(t *testing.T) {
	e := newEnv(t)
	e.addAdmin("opadmin", "adminpass1")
	stu := e.browser()
	adm := e.browser()

	// 가입 신청 → 승인 대기 화면
	if code, path, body := stu.post("/signup", signupForm("20230001", "홍길동", "studentpw1")); code != 200 || path != "/pending" || !strings.Contains(body, "승인 대기") {
		t.Fatalf("가입: %d %s", code, path)
	}
	if _, path, _ := stu.get("/me"); path != "/pending" {
		t.Fatalf("대기 중인데 %s로 갔다", path)
	}
	if _, ok := e.fake.Get("20230001"); ok {
		t.Fatal("승인 전에 OpenStack 계정이 생겼다")
	}

	// 학생은 운영진 화면을 볼 수 없다
	if code, _, _ := stu.get("/admin/users"); code != http.StatusForbidden {
		t.Fatalf("학생이 운영진 화면을 봤다: %d", code)
	}

	// 운영진 승인 → OpenStack 계정(비밀번호 없음, 켜짐)
	if _, path, _ := adm.login("opadmin", "adminpass1"); path != "/admin/users" {
		t.Fatalf("운영진 로그인 뒤 %s", path)
	}
	if _, _, body := adm.get("/admin/users?status=pending"); !strings.Contains(body, "20230001") {
		t.Fatal("대기 목록에 없다")
	}
	adm.post("/admin/users/20230001/approve", nil)
	acct, ok := e.fake.Get("20230001")
	if !ok || !acct.Enabled || acct.Password != "" || acct.Quota != cloud.DefaultQuota {
		t.Fatalf("승인 뒤 계정: %+v %v", acct, ok)
	}
	if u := e.user("20230001"); u.Status != "active" || u.CloudUserID == "" || u.CloudPasswordSynced != 0 {
		t.Fatalf("승인 뒤 DB: %+v", u)
	}

	// 학생이 비밀번호를 한 번 더 넣으면 웹 콘솔 비밀번호가 같아진다
	if _, path, body := stu.get("/"); path != "/me" || !strings.Contains(body, "웹 콘솔 비밀번호 맞추기") {
		t.Fatalf("승인 뒤 첫 화면: %s", path)
	}
	stu.post("/me/sync-password", url.Values{"password": {"wrong-pass"}})
	if a, _ := e.fake.Get("20230001"); a.Password != "" {
		t.Fatal("틀린 비밀번호로 맞췄다")
	}
	stu.post("/me/sync-password", url.Values{"password": {"studentpw1"}})
	if a, _ := e.fake.Get("20230001"); a.Password != "studentpw1" {
		t.Fatalf("웹 콘솔 비밀번호: %q", a.Password)
	}
	if _, _, body := stu.get("/me"); !strings.Contains(body, "VM 쓰는 법") {
		t.Fatal("맞춘 뒤에도 안내가 안 나온다")
	}

	// 비밀번호를 바꾸면 웹 콘솔도 같이 바뀐다
	stu.post("/me/password", url.Values{"current": {"studentpw1"}, "password": {"newpass-22"}, "password2": {"newpass-22"}})
	if a, _ := e.fake.Get("20230001"); a.Password != "newpass-22" {
		t.Fatalf("바꾼 뒤 웹 콘솔 비밀번호: %q", a.Password)
	}
	if code, _, _ := e.browser().login("20230001", "studentpw1"); code != http.StatusUnauthorized {
		t.Fatalf("옛 비밀번호로 로그인됐다: %d", code)
	}

	// 정지하면 끄고, 해제하면 켠다
	adm.post("/admin/users/20230001/suspend", nil)
	if a, _ := e.fake.Get("20230001"); a.Enabled {
		t.Fatal("정지했는데 켜져 있다")
	}
	if _, _, body := stu.get("/me"); !strings.Contains(body, "정지돼") {
		t.Fatal("학생 화면에 정지 안내가 없다")
	}
	adm.post("/admin/users/20230001/resume", nil)
	if a, _ := e.fake.Get("20230001"); !a.Enabled {
		t.Fatal("해제했는데 꺼져 있다")
	}

	// 할당량
	adm.post("/admin/users/20230001/quota", url.Values{"instances": {"3"}, "cores": {"4"}, "ram_gb": {"8"}, "floating_ips": {"2"}})
	if a, _ := e.fake.Get("20230001"); a.Quota != (cloud.Quota{Instances: 3, Cores: 4, RAMMB: 8192, FloatingIPs: 2}) {
		t.Fatalf("할당량: %+v", a.Quota)
	}
	adm.post("/admin/users/20230001/quota", url.Values{"instances": {"99"}, "cores": {"4"}, "ram_gb": {"8"}, "floating_ips": {"2"}})
	if e.user("20230001").QuotaInstances != 3 {
		t.Fatal("범위를 넘는 할당량을 받아들였다")
	}

	// 임시 비밀번호 → 포털·웹 콘솔에 같이, 로그인하면 바꾸기 화면으로
	_, _, body := adm.post("/admin/users/20230001/temp-password", nil)
	m := regexp.MustCompile(`<p class="secret"><code>([A-Za-z0-9]{12})</code>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("임시 비밀번호가 화면에 없다")
	}
	if a, _ := e.fake.Get("20230001"); a.Password != m[1] {
		t.Fatal("웹 콘솔에 임시 비밀번호가 안 들어갔다")
	}
	if _, path, _ := stu.get("/me"); path != "/login" {
		t.Fatalf("임시 비밀번호를 만들었는데 옛 로그인이 살아 있다: %s", path)
	}
	if _, path, _ := stu.login("20230001", m[1]); path != "/me/password" {
		t.Fatalf("임시 비밀번호로 로그인한 뒤 %s", path)
	}

	// 지우기: 아이디를 틀리면 그대로, 맞으면 OpenStack과 포털에서 모두 사라진다
	adm.post("/admin/users/20230001/delete", url.Values{"confirm": {"2023000"}})
	if _, ok := e.fake.Get("20230001"); !ok {
		t.Fatal("확인 없이 지웠다")
	}
	adm.post("/admin/users/20230001/delete", url.Values{"confirm": {"20230001"}})
	if _, ok := e.fake.Get("20230001"); ok {
		t.Fatal("OpenStack 계정이 남았다")
	}
	if _, err := e.st.GetUserByLogin(context.Background(), "20230001"); err == nil {
		t.Fatal("포털 계정이 남았다")
	}
	if _, _, body := adm.get("/admin/audit"); !strings.Contains(body, "삭제") || !strings.Contains(body, "승인") {
		t.Fatal("감사 로그에 작업이 안 남았다")
	}
}

func TestLoginSyncsPasswordAfterApproval(t *testing.T) {
	e := newEnv(t)
	e.addAdmin("opadmin", "adminpass1")
	e.browser().post("/signup", signupForm("20230002", "김철수", "studentpw2"))
	adm := e.browser()
	adm.login("opadmin", "adminpass1")
	adm.post("/admin/users/20230002/approve", nil)
	// 대기 화면을 닫았다가 나중에 로그인만 해도 웹 콘솔 비밀번호가 맞춰진다
	e.browser().login("20230002", "studentpw2")
	if a, _ := e.fake.Get("20230002"); a.Password != "studentpw2" {
		t.Fatalf("로그인 때 맞추지 않았다: %q", a.Password)
	}
}

func TestApproveFailureIsRetried(t *testing.T) {
	e := newEnv(t)
	e.addAdmin("opadmin", "adminpass1")
	e.browser().post("/signup", signupForm("20230003", "이영희", "studentpw3"))
	adm := e.browser()
	adm.login("opadmin", "adminpass1")
	e.fake.Fail = errors.New("keystone 연결 안 됨")
	_, _, body := adm.post("/admin/users/20230003/approve", nil)
	if !strings.Contains(body, "OpenStack에 맞추지 못했다") {
		t.Fatal("실패를 알리지 않았다")
	}
	if u := e.user("20230003"); u.Status != "active" || u.SyncError == "" {
		t.Fatalf("실패가 DB에 안 남았다: %+v", u)
	}
	if err := e.rec.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u := e.user("20230003"); u.SyncError != "" || u.CloudUserID == "" {
		t.Fatalf("다시 맞추지 못했다: %+v", u)
	}
}

func TestExpiry(t *testing.T) {
	e := newEnv(t)
	e.addAdmin("opadmin", "adminpass1")
	e.browser().post("/signup", signupForm("20230004", "박민수", "studentpw4"))
	adm := e.browser()
	adm.login("opadmin", "adminpass1")
	adm.post("/admin/users/20230004/approve", nil)
	yesterday := time.Now().In(kst).AddDate(0, 0, -1).Format("2006-01-02")
	adm.post("/admin/users/20230004/expiry", url.Values{"expires": {yesterday}})
	if err := e.rec.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u := e.user("20230004"); u.Status != "expired" {
		t.Fatalf("만료되지 않았다: %s", u.Status)
	}
	if a, _ := e.fake.Get("20230004"); a.Enabled {
		t.Fatal("만료됐는데 OpenStack 사용자가 켜져 있다")
	}
	// 다시 쓰게 하면 지난 만료일은 지운다
	adm.post("/admin/users/20230004/resume", nil)
	if u := e.user("20230004"); u.Status != "active" || u.ExpiresAt.Valid {
		t.Fatalf("해제 뒤: %s %v", u.Status, u.ExpiresAt)
	}
}

func TestSignupRules(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	cases := []struct {
		form url.Values
		code int
	}{
		{signupForm("ab", "짧음", "studentpw1"), 400},
		{signupForm("admin", "관리자", "studentpw1"), 400},
		{signupForm("20230010", "", "studentpw1"), 400},
		{signupForm("20230010", "짧은 비번", "short"), 400},
		{url.Values{"login": {"20230010"}, "name": {"다름"}, "password": {"studentpw1"}, "password2": {"studentpw2"}}, 400},
	}
	for i, c := range cases {
		if code, _, _ := b.post("/signup", c.form); code != c.code {
			t.Errorf("%d번: %d (기대 %d)", i, code, c.code)
		}
	}
	if code, _, _ := e.browser().post("/signup", signupForm("20230010", "처음", "studentpw1")); code != 200 {
		t.Fatalf("정상 가입: %d", code)
	}
	if code, _, _ := e.browser().post("/signup", signupForm("20230010", "두번째", "studentpw1")); code != http.StatusConflict {
		t.Fatalf("같은 아이디: %d", code)
	}
}

func TestSignupLimits(t *testing.T) {
	e := newEnv(t) // 대기 상한 3, IP별 1시간 4번
	for i, login := range []string{"20230021", "20230022", "20230023"} {
		if code, _, _ := e.browser().post("/signup", signupForm(login, "학생", "studentpw1")); code != 200 {
			t.Fatalf("%d번째 가입: %d", i+1, code)
		}
	}
	if code, _, _ := e.browser().post("/signup", signupForm("20230024", "학생", "studentpw1")); code != http.StatusServiceUnavailable {
		t.Fatalf("대기 상한을 넘었는데: %d", code)
	}
	if code, _, _ := e.browser().post("/signup", signupForm("20230025", "학생", "studentpw1")); code != http.StatusTooManyRequests {
		t.Fatalf("IP별 횟수를 넘었는데: %d", code)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.get("/login")
	if code, _, _ := b.post("/login", url.Values{"csrf": {"wrong"}, "login": {"x"}, "password": {"y"}}); code != http.StatusForbidden {
		t.Fatalf("CSRF 값이 틀렸는데 %d", code)
	}
	// 쿠키 없이(다른 사이트에서 보낸 것처럼)
	resp, err := http.PostForm(e.ts.URL+"/signup", signupForm("20230030", "외부", "studentpw1"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("쿠키 없는 POST가 %d", resp.StatusCode)
	}
}

func TestLoginLimit(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	for range 10 {
		b.login("20230040", "wrong-pass")
	}
	if code, _, _ := b.login("20230040", "wrong-pass"); code != http.StatusTooManyRequests {
		t.Fatalf("11번째 로그인 시도가 %d", code)
	}
}

func TestPendingSSE(t *testing.T) {
	e := newEnv(t)
	e.addAdmin("opadmin", "adminpass1")
	stu := e.browser()
	stu.post("/signup", signupForm("20230050", "최수지", "studentpw5"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.ts.URL+"/pending/events", nil)
	resp, err := stu.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type: %s", ct)
	}
	adm := e.browser()
	adm.login("opadmin", "adminpass1")
	adm.post("/admin/users/20230050/approve", nil)

	sc := bufio.NewScanner(resp.Body)
	var got strings.Builder
	for sc.Scan() {
		got.WriteString(sc.Text() + "\n")
		if strings.Contains(got.String(), "승인됐다") {
			break
		}
	}
	if !strings.Contains(got.String(), "event: status") || !strings.Contains(got.String(), "승인됐다") {
		t.Fatalf("SSE 내용: %q", got.String())
	}
}

// approved는 승인되고 웹 콘솔 비밀번호까지 맞춘 학생을 만든다.
func (e *env) approved(login string) *browser {
	e.t.Helper()
	if _, err := e.st.GetUserByLogin(context.Background(), "opadmin"); err != nil {
		e.addAdmin("opadmin", "adminpass1")
	}
	stu := e.browser()
	stu.post("/signup", signupForm(login, "VM학생", "studentpw1"))
	adm := e.browser()
	adm.login("opadmin", "adminpass1")
	adm.post("/admin/users/"+login+"/approve", nil)
	stu.post("/me/sync-password", url.Values{"password": {"studentpw1"}})
	return stu
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 100 {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: 기다려도 되지 않았다", what)
}

func TestVMLifecycle(t *testing.T) {
	e := newEnv(t)
	stu := e.approved("20230060")

	// 키가 없으면 만들 수 없다
	if _, _, body := stu.get("/me/vms"); !strings.Contains(body, "SSH 키가 없다") {
		t.Fatal("키 안내가 없다")
	}
	if code, _, _ := stu.post("/me/vms", url.Values{"name": {"web1"}, "flavor": {"s.small"}}); code != http.StatusBadRequest {
		t.Fatalf("키 없이 만들기: %d", code)
	}

	// 키 새로 만들기 → 개인 키 파일을 내려받고, 공개 키는 저장된다
	resp, err := stu.c.PostForm(e.ts.URL+"/me/key/new", url.Values{"csrf": {stu.csrf()}})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "student-cloud-key") || !strings.HasPrefix(string(priv), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("키 내려받기: %s %.30s", resp.Header.Get("Content-Disposition"), priv)
	}
	pub := e.user("20230060").SshPublicKey
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatalf("저장된 공개 키: %q", pub)
	}

	// 이름 규칙
	if code, _, _ := stu.post("/me/vms", url.Values{"name": {"Web_1"}, "flavor": {"s.small"}}); code != http.StatusBadRequest {
		t.Fatalf("잘못된 이름: %d", code)
	}

	// 만들기 → 키가 들어가고, 켜지면 유동 IP가 저절로 붙는다
	if _, path, _ := stu.post("/me/vms", url.Values{"name": {"web1"}, "flavor": {"s.small"}}); path != "/me/vms" {
		t.Fatalf("만든 뒤 %s", path)
	}
	vms := e.fake.VMList("20230060")
	if len(vms) != 1 || vms[0].SSHKey != pub || vms[0].Flavor != "s.small" {
		t.Fatalf("만든 VM: %+v", vms)
	}
	waitFor(t, "유동 IP", func() bool { return e.fake.VMList("20230060")[0].FloatingIP != "" })
	ip := e.fake.VMList("20230060")[0].FloatingIP
	if _, _, body := stu.get("/me/vms"); !strings.Contains(body, "ssh ubuntu@"+ip) || !strings.Contains(body, "켜짐") {
		t.Fatal("목록에 접속 명령이 없다")
	}
	if _, _, body := stu.post("/me/vms", url.Values{"name": {"web1"}, "flavor": {"s.tiny"}}); !strings.Contains(body, "같은 이름") {
		t.Fatal("같은 이름을 받아들였다")
	}

	// 할당량(vCPU 2를 다 씀): s.tiny 하나 더는 거부, 화면에서도 막아 둔다
	_, _, body := stu.post("/me/vms", url.Values{"name": {"web2"}, "flavor": {"s.tiny"}})
	if !strings.Contains(body, "할당량") || len(e.fake.VMList("20230060")) != 1 {
		t.Fatal("할당량을 넘겨 만들었다")
	}
	if !strings.Contains(body, `value="s.tiny"  disabled`) && !strings.Contains(body, "할당량이 모자람") {
		t.Fatal("모자란 크기를 표시하지 않았다")
	}

	id := e.fake.VMList("20230060")[0].ID
	act := func(action string) { stu.post("/me/vms/"+id+"/do/"+action, nil) }
	act("stop")
	if st := e.fake.VMList("20230060")[0].Status; st != "SHUTOFF" {
		t.Fatalf("끄기: %s", st)
	}
	act("stop") // 이미 꺼져 있다
	if _, _, body := stu.get("/me/vms"); !strings.Contains(body, "꺼짐") {
		t.Fatal("꺼짐 표시가 없다")
	}
	act("start")
	act("reboot")
	if st := e.fake.VMList("20230060")[0].Status; st != "ACTIVE" {
		t.Fatalf("켜기·다시 시작: %s", st)
	}
	act("detach-ip")
	if e.fake.VMList("20230060")[0].FloatingIP != "" {
		t.Fatal("유동 IP를 떼지 못했다")
	}
	act("attach-ip")
	if e.fake.VMList("20230060")[0].FloatingIP == "" {
		t.Fatal("유동 IP를 붙이지 못했다")
	}

	// 다른 학생의 VM은 건드리지 못한다
	other := e.approved("20230061")
	other.post("/me/vms/"+id+"/do/stop", nil)
	other.post("/me/vms/"+id+"/delete", nil)
	if vms := e.fake.VMList("20230060"); len(vms) != 1 || vms[0].Status != "ACTIVE" {
		t.Fatalf("다른 학생이 VM을 건드렸다: %+v", vms)
	}

	// 지우기: 확인 화면 → 지움
	if _, _, body := stu.get("/me/vms/" + id + "/delete"); !strings.Contains(body, "web1") || !strings.Contains(body, "되돌릴 수 없다") {
		t.Fatal("지우기 확인 화면")
	}
	stu.post("/me/vms/"+id+"/delete", nil)
	if len(e.fake.VMList("20230060")) != 0 {
		t.Fatal("지우지 못했다")
	}

	// 정지된 학생은 포털로도 VM을 다루지 못한다
	adm := e.browser()
	adm.login("opadmin", "adminpass1")
	adm.post("/admin/users/20230060/suspend", nil)
	if code, _, _ := stu.get("/me/vms"); code != http.StatusForbidden {
		t.Fatalf("정지된 학생의 VM 화면: %d", code)
	}
	if code, _, _ := stu.post("/me/vms", url.Values{"name": {"web3"}, "flavor": {"s.tiny"}}); code != http.StatusForbidden {
		t.Fatalf("정지된 학생의 VM 만들기: %d", code)
	}
}

func TestSSHKeyPaste(t *testing.T) {
	e := newEnv(t)
	stu := e.approved("20230070")
	if code, _, body := stu.post("/me/key", url.Values{"key": {"-----BEGIN OPENSSH PRIVATE KEY-----\nabc"}}); code != http.StatusBadRequest || !strings.Contains(body, "개인 키") {
		t.Fatalf("개인 키를 받아들였다: %d", code)
	}
	_, pub, _ := auth.GenerateSSHKey("me@laptop")
	if _, path, _ := stu.post("/me/key", url.Values{"key": {pub}}); path != "/me/vms" {
		t.Fatalf("공개 키 등록 뒤 %s", path)
	}
	if e.user("20230070").SshPublicKey != pub {
		t.Fatal("공개 키가 저장되지 않았다")
	}
}

func TestVMSSE(t *testing.T) {
	e := newEnv(t)
	stu := e.approved("20230080")
	_, pub, _ := auth.GenerateSSHKey("x")
	stu.post("/me/key", url.Values{"key": {pub}})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.ts.URL+"/me/vms/events", nil)
	resp, err := stu.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	stu.post("/me/vms", url.Values{"name": {"sse1"}, "flavor": {"s.tiny"}})
	sc := bufio.NewScanner(resp.Body)
	var got strings.Builder
	for sc.Scan() {
		got.WriteString(sc.Text() + "\n")
		if strings.Contains(got.String(), "sse1") {
			break
		}
	}
	if !strings.Contains(got.String(), "event: vms") || !strings.Contains(got.String(), "sse1") {
		t.Fatalf("SSE 내용: %q", got.String())
	}
}

func TestFlashKeepsPlus(t *testing.T) {
	e := newEnv(t)
	stu := e.approved("20230090")
	// 지문에 '+'가 들어간 키가 나올 때까지 만든다(반쯤은 들어 있다).
	var pub, fp string
	for range 50 {
		_, pub, _ = auth.GenerateSSHKey("x")
		if fp = auth.SSHKeyFingerprint(pub); strings.Contains(fp, "+") {
			break
		}
	}
	if !strings.Contains(fp, "+") {
		t.Skip("'+'가 든 지문을 만들지 못했다")
	}
	// 지문은 VM 화면 다른 곳에도 나오므로 알림 문단만 본다. html/template은 '+'를 &#43;로 쓴다.
	_, _, body := stu.post("/me/key", url.Values{"key": {pub}})
	m := regexp.MustCompile(`<p class="flash ok"[^>]*>([^<]*)</p>`).FindStringSubmatch(body)
	if m == nil || !strings.Contains(html.UnescapeString(m[1]), fp) {
		t.Fatalf("알림에서 지문 %s가 깨졌다: %v", fp, m)
	}
}
