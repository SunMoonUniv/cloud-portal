// Package web은 포털 화면이다. 서버에서 HTML을 그리고(html/template), 승인 대기 화면만 SSE(htmx)를 쓴다.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"cloud-portal/internal/auth"
	"cloud-portal/internal/cloud"
	"cloud-portal/internal/reconcile"
	"cloud-portal/internal/store"
	"cloud-portal/internal/store/db"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Config struct {
	ConsoleURL    string        // 웹 콘솔(Horizon) 주소
	PendingMax    int           // 승인 대기 인원 상한
	SignupPerHour int           // IP별 1시간 가입 신청 횟수
	SessionTTL    time.Duration // 로그인 유지 시간
	SecureCookie  bool          // HTTPS일 때만 true(MVP-0은 HTTP)
}

type Server struct {
	cfg        Config
	st         *store.Store
	cl         cloud.Cloud
	rec        *reconcile.Reconciler
	log        *slog.Logger
	pages      map[string]*template.Template
	signupIP   *auth.Limiter
	loginIP    *auth.Limiter
	loginLogin *auth.Limiter
	autoIP     sync.Map // 유동 IP를 붙이려고 켜지기를 기다리는 VM ID
}

func New(cfg Config, st *store.Store, cl cloud.Cloud, rec *reconcile.Reconciler, log *slog.Logger) (*Server, error) {
	s := &Server{
		cfg: cfg, st: st, cl: cl, rec: rec, log: log,
		signupIP:   auth.NewLimiter(cfg.SignupPerHour, time.Hour),
		loginIP:    auth.NewLimiter(30, 10*time.Minute),
		loginLogin: auth.NewLimiter(10, 10*time.Minute),
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

var kst = time.FixedZone("KST", 9*60*60)

var statusLabels = map[string]string{
	"pending": "승인 대기", "active": "사용 중", "suspended": "정지", "expired": "만료", "rejected": "거절",
}

var funcs = template.FuncMap{
	"status": func(s string) string { return statusLabels[s] },
	"datetime": func(unix int64) string {
		return time.Unix(unix, 0).In(kst).Format("2006-01-02 15:04")
	},
	"nulltime": func(n sql.NullInt64) string {
		if !n.Valid {
			return ""
		}
		return time.Unix(n.Int64, 0).In(kst).Format("2006-01-02 15:04")
	},
	"nulldate": func(n sql.NullInt64) string {
		if !n.Valid {
			return ""
		}
		return time.Unix(n.Int64, 0).In(kst).Format("2006-01-02")
	},
	"add1":     func(n int) int { return n + 1 },
	"vmuser":   func() string { return cloud.VMUser },
	"hasquota": func(msg string) bool { return strings.Contains(msg, "Quota exceeded") },
	// vmbtn은 VM 작업 버튼 하나를 그릴 값을 묶는다.
	"vmbtn": func(csrf, id, action, label, class string) map[string]string {
		return map[string]string{"CSRF": csrf, "ID": id, "Action": action, "Label": label, "Class": class}
	},
	"sub1": func(n int) int { return n - 1 },
	"gb": func(mb int64) string {
		if mb%1024 == 0 {
			return fmt.Sprintf("%dGB", mb/1024)
		}
		return fmt.Sprintf("%.1fGB", float64(mb)/1024)
	},
	"intgb": func(mb int) string {
		if mb%1024 == 0 {
			return fmt.Sprintf("%dGB", mb/1024)
		}
		return fmt.Sprintf("%.1fGB", float64(mb)/1024)
	},
}

// 화면마다 base.html과 그 화면 파일을 묶은 템플릿을 하나씩 만든다.
func (s *Server) parseTemplates() error {
	s.pages = map[string]*template.Template{}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	for _, n := range names {
		name := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
		if name == "base" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(templateFS, "templates/base.html", n)
		if err != nil {
			return fmt.Errorf("템플릿 %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

// page는 모든 화면이 받는 값이다. 화면별 값은 Data에 넣는다.
type page struct {
	Title      string
	User       *db.User
	CSRF       string
	Flash      string
	FlashKind  string
	ConsoleURL string
	Error      string
	Data       any
}

func (s *Server) render(c *gin.Context, status int, name, title string, data any) {
	s.renderErr(c, status, name, title, "", data)
}

func (s *Server) renderErr(c *gin.Context, status int, name, title, errMsg string, data any) {
	p := page{
		Title: title, CSRF: c.GetString("csrf"), ConsoleURL: s.cfg.ConsoleURL, Error: errMsg, Data: data,
	}
	if u, ok := c.Get("user"); ok {
		uu := u.(db.User)
		p.User = &uu
	}
	p.FlashKind, p.Flash = takeFlash(c)
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "base", p); err != nil {
		s.log.Error("화면 그리기", "page", name, "err", err)
		c.String(http.StatusInternalServerError, "화면을 그리지 못했다")
		return
	}
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}

// fragment는 base 없이 템플릿 하나만 그린다(SSE로 보내는 조각).
func (s *Server) fragment(page, name string, data any) (string, error) {
	var buf bytes.Buffer
	err := s.pages[page].ExecuteTemplate(&buf, name, data)
	return buf.String(), err
}

func (s *Server) Handler() http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil) // 앞에 프록시가 없다. X-Forwarded-For를 믿지 않는다
	r.Use(gin.Recovery(), s.accessLog, securityHeaders, limitBody, s.csrf, s.loadUser)

	static, _ := fs.Sub(staticFS, "static")
	r.StaticFS("/static", http.FS(static))

	r.GET("/", s.home)
	r.GET("/signup", s.signupForm)
	r.POST("/signup", s.signup)
	r.GET("/login", s.loginForm)
	r.POST("/login", s.login)
	r.POST("/logout", s.logout)

	st := r.Group("/", s.requireRole("student"))
	st.GET("/pending", s.pending)
	st.GET("/pending/events", s.pendingEvents)
	st.GET("/me", s.me)
	st.POST("/me/sync-password", s.syncPassword)

	vm := st.Group("/", s.requireActive)
	vm.GET("/me/vms", s.vmsPage)
	vm.GET("/me/vms/events", s.vmsEvents)
	vm.POST("/me/vms", s.createVM)
	vm.GET("/me/vms/:id/delete", s.deleteVMForm)
	vm.POST("/me/vms/:id/delete", s.deleteVM)
	vm.POST("/me/vms/:id/do/:action", s.vmAction)
	vm.GET("/me/key", s.keyPage)
	vm.POST("/me/key", s.saveKey)
	vm.POST("/me/key/new", s.newKey)

	// 비밀번호 바꾸기는 학생과 운영진 모두 쓴다.
	lg := r.Group("/", s.requireRole(""))
	lg.GET("/me/password", s.passwordForm)
	lg.POST("/me/password", s.changePassword)

	ad := r.Group("/admin", s.requireRole("admin"))
	ad.GET("", func(c *gin.Context) { c.Redirect(http.StatusSeeOther, "/admin/users?status=pending") })
	ad.GET("/users", s.adminUsers)
	ad.GET("/users/:login", s.adminUser)
	ad.POST("/users/:login/:action", s.adminAction)
	ad.GET("/audit", s.adminAudit)
	ad.GET("/orphans", s.adminOrphans)

	r.NoRoute(func(c *gin.Context) {
		s.render(c, http.StatusNotFound, "error", "없는 화면", "찾는 화면이 없다.")
	})
	return r
}

func (s *Server) accessLog(c *gin.Context) {
	start := time.Now()
	c.Next()
	if strings.HasPrefix(c.Request.URL.Path, "/static/") {
		return
	}
	s.log.Info("요청", "method", c.Request.Method, "path", c.Request.URL.Path, "status", c.Writer.Status(),
		"ip", c.ClientIP(), "ms", time.Since(start).Milliseconds())
}

func securityHeaders(c *gin.Context) {
	h := c.Writer.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
		"connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
	c.Next()
}

func limitBody(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10)
	c.Next()
}

// csrf는 쿠키에 무작위 값을 두고, POST마다 폼(csrf) 또는 헤더(X-CSRF-Token)에 같은 값이 있는지 본다.
// 쿠키는 SameSite=Strict라서 다른 사이트에서 보낸 요청에는 실리지 않는다.
func (s *Server) csrf(c *gin.Context) {
	token, err := c.Cookie("csrf")
	if err != nil || len(token) < 20 {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		token = base64.RawURLEncoding.EncodeToString(b)
		s.setCookie(c, "csrf", token, 0, http.SameSiteStrictMode)
	}
	c.Set("csrf", token)
	if c.Request.Method == http.MethodPost {
		got := c.GetHeader("X-CSRF-Token")
		if got == "" {
			got = c.PostForm("csrf")
		}
		if got != token {
			s.render(c, http.StatusForbidden, "error", "요청 거부", "화면이 오래됐다. 새로 고친 뒤 다시 한다.")
			c.Abort()
			return
		}
	}
	c.Next()
}

func (s *Server) setCookie(c *gin.Context, name, value string, maxAge int, same http.SameSite) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.SecureCookie, SameSite: same,
	})
}

func (s *Server) loadUser(c *gin.Context) {
	if token, err := c.Cookie("session"); err == nil && token != "" {
		u, err := s.st.GetSessionUser(c, db.GetSessionUserParams{TokenHash: auth.HashToken(token), ExpiresAt: time.Now().Unix()})
		if err == nil {
			c.Set("user", u)
		}
	}
	c.Next()
}

func currentUser(c *gin.Context) (db.User, bool) {
	u, ok := c.Get("user")
	if !ok {
		return db.User{}, false
	}
	return u.(db.User), true
}

func (s *Server) requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		u, ok := currentUser(c)
		if !ok {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		if role != "" && u.Role != role {
			s.render(c, http.StatusForbidden, "error", "권한 없음", "이 화면을 볼 권한이 없다.")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) startSession(c *gin.Context, userID int64) error {
	token, hash := auth.NewToken()
	now := time.Now()
	if err := s.st.CreateSession(c, db.CreateSessionParams{
		TokenHash: hash, UserID: userID, CreatedAt: now.Unix(), ExpiresAt: now.Add(s.cfg.SessionTTL).Unix(),
	}); err != nil {
		return err
	}
	s.setCookie(c, "session", token, int(s.cfg.SessionTTL.Seconds()), http.SameSiteLaxMode)
	return nil
}

// flash는 다음 화면 한 번만 보이는 알림이다. kind는 ok 또는 err.
func (s *Server) flash(c *gin.Context, kind, msg string) {
	s.setCookie(c, "flash", url.QueryEscape(kind+"|"+msg), 60, http.SameSiteLaxMode)
}

func takeFlash(c *gin.Context) (kind, msg string) {
	v, err := c.Cookie("flash")
	if err != nil || v == "" {
		return "", ""
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "flash", Path: "/", MaxAge: -1})
	// gin의 Cookie가 이미 한 번 풀어 준다. 다시 풀면 '+'가 공백이 된다.
	kind, msg, _ = strings.Cut(v, "|")
	return kind, msg
}

func (s *Server) home(c *gin.Context) {
	u, ok := currentUser(c)
	switch {
	case !ok:
		c.Redirect(http.StatusSeeOther, "/login")
	case u.Role == "admin":
		c.Redirect(http.StatusSeeOther, "/admin")
	case u.Status == "pending":
		c.Redirect(http.StatusSeeOther, "/pending")
	case u.MustChangePassword == 1:
		c.Redirect(http.StatusSeeOther, "/me/password")
	default:
		c.Redirect(http.StatusSeeOther, "/me")
	}
}

// cloudCtx는 화면 요청 안에서 OpenStack을 부를 때 쓰는 시간 제한이다.
func cloudCtx(c *gin.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request.Context(), 30*time.Second)
}

var errNoAccount = errors.New("OpenStack 계정이 아직 준비되지 않았다")
