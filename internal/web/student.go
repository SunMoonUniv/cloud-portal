package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"cloud-portal/internal/auth"
	"cloud-portal/internal/cloud"
	"cloud-portal/internal/store/db"
)

type signupData struct{ Login, Name string }

func (s *Server) signupForm(c *gin.Context) {
	if _, ok := currentUser(c); ok {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}
	s.render(c, http.StatusOK, "signup", "가입 신청", signupData{})
}

func (s *Server) signup(c *gin.Context) {
	login := strings.TrimSpace(c.PostForm("login"))
	name, nameOK := auth.CleanName(c.PostForm("name"))
	pw := c.PostForm("password")
	form := signupData{Login: login, Name: name}
	fail := func(status int, msg string) { s.renderErr(c, status, "signup", "가입 신청", msg, form) }

	switch {
	case !auth.ValidLogin(login):
		fail(http.StatusBadRequest, "아이디는 영문·숫자·._- 3~32자로 쓴다(학번을 권한다).")
		return
	case auth.Reserved(login):
		fail(http.StatusBadRequest, "쓸 수 없는 아이디다. 학번을 쓴다.")
		return
	case !nameOK:
		fail(http.StatusBadRequest, "이름은 1~40자로 쓴다.")
		return
	case !auth.ValidPassword(pw):
		fail(http.StatusBadRequest, fmt.Sprintf("비밀번호는 %d~%d자로 쓴다.", auth.MinPasswordLen, auth.MaxPasswordLen))
		return
	case pw != c.PostForm("password2"):
		fail(http.StatusBadRequest, "두 비밀번호가 다르다.")
		return
	}
	if !s.signupIP.Allow(c.ClientIP()) {
		fail(http.StatusTooManyRequests, "이 컴퓨터에서 가입 신청이 너무 많았다. 1시간 뒤에 다시 한다.")
		return
	}
	if n, err := s.st.CountByStatus(c, "pending"); err != nil || int(n) >= s.cfg.PendingMax {
		fail(http.StatusServiceUnavailable, "지금은 승인 대기 인원이 꽉 찼다. 운영진에게 문의한다.")
		return
	}
	if _, err := s.st.GetUserByLogin(c, login); err == nil {
		fail(http.StatusConflict, "이미 가입 신청한 아이디다. 로그인한다.")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fail(http.StatusInternalServerError, "비밀번호를 저장하지 못했다.")
		return
	}
	now := time.Now().Unix()
	u, err := s.st.CreateUser(c, db.CreateUserParams{
		Login: login, Name: name, PasswordHash: hash, Role: "student", Status: "pending",
		SignupIp: c.ClientIP(), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		fail(http.StatusConflict, "이미 있는 아이디다.")
		return
	}
	s.st.Audit(c, login, "가입 신청", login, name+" ("+c.ClientIP()+")")
	if err := s.startSession(c, u.ID); err != nil {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	c.Redirect(http.StatusSeeOther, "/pending")
}

type loginData struct{ Login string }

func (s *Server) loginForm(c *gin.Context) {
	if _, ok := currentUser(c); ok {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}
	s.render(c, http.StatusOK, "login", "로그인", loginData{})
}

// 없는 아이디로 로그인해도 걸리는 시간이 같도록 비교할 해시다.
var dummyHash, _ = auth.HashPassword("dummy-password-for-timing")

func (s *Server) login(c *gin.Context) {
	login := strings.TrimSpace(c.PostForm("login"))
	pw := c.PostForm("password")
	form := loginData{Login: login}
	if !s.loginIP.Allow(c.ClientIP()) || !s.loginLogin.Allow(login) {
		s.renderErr(c, http.StatusTooManyRequests, "login", "로그인", "로그인 시도가 너무 많았다. 10분 뒤에 다시 한다.", form)
		return
	}
	u, err := s.st.GetUserByLogin(c, login)
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	ok, _ := auth.VerifyPassword(hash, pw)
	if err != nil || !ok {
		s.renderErr(c, http.StatusUnauthorized, "login", "로그인", "아이디 또는 비밀번호가 맞지 않다.", form)
		return
	}
	if u.Status == "rejected" {
		s.renderErr(c, http.StatusForbidden, "login", "로그인", "가입 신청이 거절됐다. 운영진에게 문의한다.", form)
		return
	}
	if err := s.startSession(c, u.ID); err != nil {
		s.renderErr(c, http.StatusInternalServerError, "login", "로그인", "로그인을 저장하지 못했다.", form)
		return
	}
	// 승인 뒤 웹 콘솔 비밀번호를 아직 맞추지 않았다면, 지금 입력한 비밀번호로 맞춘다.
	if u.Role == "student" && u.Status == "active" && u.CloudUserID != "" && u.CloudPasswordSynced == 0 {
		if err := s.pushPassword(c, u, pw); err != nil {
			s.flash(c, "err", "웹 콘솔 비밀번호를 맞추지 못했다. 내 정보 화면에서 다시 한다.")
		}
	}
	c.Redirect(http.StatusSeeOther, "/")
}

func (s *Server) logout(c *gin.Context) {
	if token, err := c.Cookie("session"); err == nil {
		_ = s.st.DeleteSession(c, auth.HashToken(token))
	}
	s.setCookie(c, "session", "", -1, http.SameSiteLaxMode)
	c.Redirect(http.StatusSeeOther, "/login")
}

// pushPassword는 Keystone 비밀번호를 포털 비밀번호와 같은 값으로 넣는다. 평문은 이 순간에만 쓴다.
func (s *Server) pushPassword(c *gin.Context, u db.User, pw string) error {
	if u.CloudUserID == "" {
		return errNoAccount
	}
	ctx, cancel := cloudCtx(c)
	defer cancel()
	if err := s.cl.SetPassword(ctx, u.CloudUserID, pw); err != nil {
		s.log.Warn("웹 콘솔 비밀번호 맞추기", "login", u.Login, "err", err)
		return err
	}
	return s.st.SetCloudPasswordSynced(c, db.SetCloudPasswordSyncedParams{
		CloudPasswordSynced: 1, UpdatedAt: time.Now().Unix(), ID: u.ID,
	})
}

func (s *Server) pending(c *gin.Context) {
	u, _ := currentUser(c)
	if u.Status != "pending" {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}
	s.render(c, http.StatusOK, "pending", "승인 대기", nil)
}

// pendingEvents는 승인 대기 화면이 연결하는 SSE다. 상태가 바뀌면 조각 하나를 보내고 끝낸다.
func (s *Server) pendingEvents(c *gin.Context) {
	u, _ := currentUser(c)
	h := c.Writer.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	c.Writer.Flush()

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Minute)
	defer cancel()
	check := time.NewTicker(3 * time.Second)
	defer check.Stop()
	beat := time.NewTicker(20 * time.Second)
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-beat.C:
			fmt.Fprint(c.Writer, ": keep-alive\n\n")
			c.Writer.Flush()
		case <-check.C:
			cur, err := s.st.GetUser(ctx, u.ID)
			if err != nil || cur.Status == "pending" {
				continue
			}
			html, err := s.fragment("pending", "decided", cur)
			if err != nil {
				return
			}
			fmt.Fprint(c.Writer, "event: status\n")
			for _, line := range strings.Split(html, "\n") {
				fmt.Fprintf(c.Writer, "data: %s\n", line)
			}
			fmt.Fprint(c.Writer, "\n")
			c.Writer.Flush()
			return
		}
	}
}

type meData struct {
	Usage    *cloud.Usage
	UsageErr bool
}

func (s *Server) me(c *gin.Context) {
	u, _ := currentUser(c)
	if u.Status == "pending" {
		c.Redirect(http.StatusSeeOther, "/pending")
		return
	}
	if u.MustChangePassword == 1 {
		c.Redirect(http.StatusSeeOther, "/me/password")
		return
	}
	var d meData
	if u.CloudProjectID != "" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		if usage, err := s.cl.Usage(ctx, u.CloudProjectID); err == nil {
			d.Usage = &usage
		} else {
			d.UsageErr = true
		}
	}
	s.render(c, http.StatusOK, "me", "내 정보", d)
}

func (s *Server) syncPassword(c *gin.Context) {
	u, _ := currentUser(c)
	if !s.loginLogin.Allow(u.Login) {
		s.flash(c, "err", "시도가 너무 많았다. 10분 뒤에 다시 한다.")
		c.Redirect(http.StatusSeeOther, "/me")
		return
	}
	pw := c.PostForm("password")
	if ok, _ := auth.VerifyPassword(u.PasswordHash, pw); !ok {
		s.flash(c, "err", "비밀번호가 맞지 않다.")
		c.Redirect(http.StatusSeeOther, "/me")
		return
	}
	if u.Status != "active" {
		s.flash(c, "err", "사용 중인 계정만 웹 콘솔 비밀번호를 맞출 수 있다.")
		c.Redirect(http.StatusSeeOther, "/me")
		return
	}
	if u.CloudUserID == "" {
		// 승인 때 계정 만들기가 실패했으면 한 번 더 해 본다.
		ctx, cancel := cloudCtx(c)
		defer cancel()
		u, _ = s.rec.SyncLogin(ctx, u.Login)
	}
	if err := s.pushPassword(c, u, pw); err != nil {
		s.flash(c, "err", "웹 콘솔 비밀번호를 맞추지 못했다. 잠시 뒤 다시 하거나 운영진에게 문의한다.")
	} else {
		s.st.Audit(c, u.Login, "웹 콘솔 비밀번호 맞춤", u.Login, "")
		s.flash(c, "ok", "웹 콘솔 비밀번호를 포털 비밀번호와 같게 맞췄다.")
	}
	c.Redirect(http.StatusSeeOther, "/me")
}

func (s *Server) passwordForm(c *gin.Context) {
	s.render(c, http.StatusOK, "password", "비밀번호 바꾸기", nil)
}

func (s *Server) changePassword(c *gin.Context) {
	u, _ := currentUser(c)
	cur, pw := c.PostForm("current"), c.PostForm("password")
	fail := func(status int, msg string) { s.renderErr(c, status, "password", "비밀번호 바꾸기", msg, nil) }
	if !s.loginLogin.Allow(u.Login) {
		fail(http.StatusTooManyRequests, "시도가 너무 많았다. 10분 뒤에 다시 한다.")
		return
	}
	if ok, _ := auth.VerifyPassword(u.PasswordHash, cur); !ok {
		fail(http.StatusBadRequest, "지금 비밀번호가 맞지 않다.")
		return
	}
	switch {
	case !auth.ValidPassword(pw):
		fail(http.StatusBadRequest, fmt.Sprintf("새 비밀번호는 %d~%d자로 쓴다.", auth.MinPasswordLen, auth.MaxPasswordLen))
		return
	case pw != c.PostForm("password2"):
		fail(http.StatusBadRequest, "두 새 비밀번호가 다르다.")
		return
	case pw == cur:
		fail(http.StatusBadRequest, "지금과 다른 비밀번호를 쓴다.")
		return
	}
	// 웹 콘솔 쪽을 먼저 바꾼다. 실패하면 포털 비밀번호도 그대로 둬서 둘이 어긋나지 않게 한다.
	synced := u.CloudPasswordSynced
	if u.Role == "student" && u.CloudUserID != "" {
		ctx, cancel := cloudCtx(c)
		defer cancel()
		if err := s.cl.SetPassword(ctx, u.CloudUserID, pw); err != nil {
			s.log.Warn("웹 콘솔 비밀번호 바꾸기", "login", u.Login, "err", err)
			fail(http.StatusBadGateway, "웹 콘솔 비밀번호를 바꾸지 못해 그대로 두었다. 잠시 뒤 다시 한다.")
			return
		}
		synced = 1
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fail(http.StatusInternalServerError, "비밀번호를 저장하지 못했다.")
		return
	}
	now := time.Now().Unix()
	if err := s.st.SetPassword(c, db.SetPasswordParams{PasswordHash: hash, MustChangePassword: 0, UpdatedAt: now, ID: u.ID}); err != nil {
		fail(http.StatusInternalServerError, "비밀번호를 저장하지 못했다.")
		return
	}
	_ = s.st.SetCloudPasswordSynced(c, db.SetCloudPasswordSyncedParams{CloudPasswordSynced: synced, UpdatedAt: now, ID: u.ID})
	// 다른 곳에 남은 로그인은 모두 끊고, 지금 화면만 새로 로그인시킨다.
	_ = s.st.DeleteUserSessions(c, u.ID)
	_ = s.startSession(c, u.ID)
	s.st.Audit(c, u.Login, "비밀번호 변경", u.Login, "")
	if synced == 1 {
		s.flash(c, "ok", "비밀번호를 바꿨다. 웹 콘솔 비밀번호도 같이 바뀌었다.")
	} else {
		s.flash(c, "ok", "비밀번호를 바꿨다.")
	}
	c.Redirect(http.StatusSeeOther, "/")
}
