package web

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"cloud-portal/internal/auth"
	"cloud-portal/internal/cloud"
	"cloud-portal/internal/store/db"
)

var statusOrder = []string{"pending", "active", "suspended", "expired", "rejected"}

type usersData struct {
	Status   string
	Statuses []string
	Counts   map[string]int64
	Users    []db.User
}

func (s *Server) adminUsers(c *gin.Context) {
	status := c.DefaultQuery("status", "pending")
	d := usersData{Status: status, Statuses: statusOrder, Counts: map[string]int64{}}
	for _, st := range statusOrder {
		d.Counts[st], _ = s.st.CountByStatus(c, st)
	}
	var err error
	if status == "all" {
		d.Users, err = s.st.ListStudents(c)
	} else {
		d.Users, err = s.st.ListStudentsByStatus(c, status)
	}
	if err != nil {
		s.render(c, http.StatusInternalServerError, "error", "오류", "목록을 읽지 못했다.")
		return
	}
	s.render(c, http.StatusOK, "admin_users", "학생 목록", d)
}

type userData struct {
	U        db.User
	Usage    *cloud.Usage
	UsageErr bool
	RAMGB    int64
}

// student는 주소의 아이디로 학생을 찾는다. 운영진 계정은 화면에서 다루지 않는다(서버 명령으로).
func (s *Server) student(c *gin.Context) (db.User, bool) {
	u, err := s.st.GetUserByLogin(c, c.Param("login"))
	if err != nil || u.Role != "student" {
		s.render(c, http.StatusNotFound, "error", "없는 학생", "그런 학생이 없다.")
		return u, false
	}
	return u, true
}

func (s *Server) adminUser(c *gin.Context) {
	u, ok := s.student(c)
	if !ok {
		return
	}
	d := userData{U: u, RAMGB: u.QuotaRamMb / 1024}
	if u.CloudProjectID != "" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		if usage, err := s.cl.Usage(ctx, u.CloudProjectID); err == nil {
			d.Usage = &usage
		} else {
			d.UsageErr = true
		}
	}
	s.render(c, http.StatusOK, "admin_user", u.Login, d)
}

type tempData struct {
	U        db.User
	Password string
	Synced   bool
}

func (s *Server) adminAction(c *gin.Context) {
	admin, _ := currentUser(c)
	u, ok := s.student(c)
	if !ok {
		return
	}
	back := "/admin/users/" + u.Login
	now := time.Now().Unix()
	setStatus := func(status string) error {
		return s.st.SetStatus(c, db.SetStatusParams{Status: status, UpdatedAt: now, ID: u.ID})
	}
	audit := func(action, detail string) { s.st.Audit(c, admin.Login, action, u.Login, detail) }
	// sync는 바뀐 내용을 OpenStack에 바로 맞추고, 결과를 알림으로 남긴다.
	sync := func(okMsg string) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
		defer cancel()
		if _, err := s.rec.SyncLogin(ctx, u.Login); err != nil {
			s.flash(c, "err", okMsg+" 다만 OpenStack에 맞추지 못했다: "+err.Error()+" (5분마다 다시 시도한다)")
		} else {
			s.flash(c, "ok", okMsg)
		}
	}
	wrongState := func() {
		s.flash(c, "err", fmt.Sprintf("지금 상태(%s)에서는 할 수 없다.", statusLabels[u.Status]))
		c.Redirect(http.StatusSeeOther, back)
	}

	switch c.Param("action") {
	case "approve":
		if u.Status != "pending" {
			wrongState()
			return
		}
		_ = setStatus("active")
		audit("승인", "")
		sync("승인했다. OpenStack 계정을 만들었다.")
		c.Redirect(http.StatusSeeOther, "/admin/users?status=pending")

	case "reject":
		if u.Status != "pending" {
			wrongState()
			return
		}
		_ = setStatus("rejected")
		_ = s.st.DeleteUserSessions(c, u.ID)
		audit("거절", "")
		s.flash(c, "ok", u.Name+"("+u.Login+")의 가입 신청을 거절했다.")
		c.Redirect(http.StatusSeeOther, "/admin/users?status=pending")

	case "suspend":
		if u.Status != "active" {
			wrongState()
			return
		}
		_ = setStatus("suspended")
		audit("정지", "")
		sync("정지했다. 웹 콘솔 로그인이 막혔다(VM은 그대로).")
		c.Redirect(http.StatusSeeOther, back)

	case "resume":
		if u.Status != "suspended" && u.Status != "expired" {
			wrongState()
			return
		}
		msg := "다시 쓸 수 있게 했다."
		if u.ExpiresAt.Valid && u.ExpiresAt.Int64 <= now {
			_ = s.st.SetExpiry(c, db.SetExpiryParams{ExpiresAt: sql.NullInt64{}, UpdatedAt: now, ID: u.ID})
			msg += " 지난 만료일은 지웠다."
		}
		_ = setStatus("active")
		audit("정지 해제", "")
		sync(msg)
		c.Redirect(http.StatusSeeOther, back)

	case "expiry":
		v := strings.TrimSpace(c.PostForm("expires"))
		exp := sql.NullInt64{}
		if v != "" {
			day, err := time.ParseInLocation("2006-01-02", v, kst)
			if err != nil {
				s.flash(c, "err", "만료일은 2026-12-31처럼 쓴다.")
				c.Redirect(http.StatusSeeOther, back)
				return
			}
			// 그날이 끝날 때(23:59:59 KST) 만료된다.
			exp = sql.NullInt64{Int64: day.AddDate(0, 0, 1).Unix() - 1, Valid: true}
		}
		_ = s.st.SetExpiry(c, db.SetExpiryParams{ExpiresAt: exp, UpdatedAt: now, ID: u.ID})
		if v == "" {
			audit("만료일", "없음")
			s.flash(c, "ok", "만료일을 지웠다.")
		} else {
			audit("만료일", v)
			s.flash(c, "ok", "만료일을 "+v+"로 정했다. 그날이 지나면 웹 콘솔 로그인이 막힌다.")
		}
		c.Redirect(http.StatusSeeOther, back)

	case "quota":
		q, err := parseQuota(c)
		if err != nil {
			s.flash(c, "err", err.Error())
			c.Redirect(http.StatusSeeOther, back)
			return
		}
		_ = s.st.SetQuota(c, db.SetQuotaParams{
			QuotaInstances: int64(q.Instances), QuotaCores: int64(q.Cores), QuotaRamMb: int64(q.RAMMB),
			QuotaFloatingIps: int64(q.FloatingIPs), UpdatedAt: now, ID: u.ID,
		})
		detail := fmt.Sprintf("VM %d, vCPU %d, RAM %dGB, 유동 IP %d", q.Instances, q.Cores, q.RAMMB/1024, q.FloatingIPs)
		audit("할당량", detail)
		if u.Status == "active" {
			sync("할당량을 바꿨다: " + detail)
		} else {
			s.flash(c, "ok", "할당량을 바꿨다: "+detail+" (사용 중이 되면 적용된다)")
		}
		c.Redirect(http.StatusSeeOther, back)

	case "temp-password":
		pw := auth.TempPassword()
		hash, err := auth.HashPassword(pw)
		if err != nil {
			s.flash(c, "err", "임시 비밀번호를 만들지 못했다.")
			c.Redirect(http.StatusSeeOther, back)
			return
		}
		synced := int64(0)
		if u.CloudUserID != "" {
			ctx, cancel := cloudCtx(c)
			err := s.cl.SetPassword(ctx, u.CloudUserID, pw)
			cancel()
			if err != nil {
				s.flash(c, "err", "웹 콘솔 비밀번호를 바꾸지 못해 임시 비밀번호를 만들지 않았다: "+err.Error())
				c.Redirect(http.StatusSeeOther, back)
				return
			}
			synced = 1
		}
		_ = s.st.SetPassword(c, db.SetPasswordParams{PasswordHash: hash, MustChangePassword: 1, UpdatedAt: now, ID: u.ID})
		_ = s.st.SetCloudPasswordSynced(c, db.SetCloudPasswordSyncedParams{CloudPasswordSynced: synced, UpdatedAt: now, ID: u.ID})
		_ = s.st.DeleteUserSessions(c, u.ID)
		audit("임시 비밀번호", "")
		// 비밀번호는 이 화면에서 한 번만 보여 준다. 어디에도 저장하지 않는다.
		c.Header("Cache-Control", "no-store")
		s.render(c, http.StatusOK, "admin_temp", "임시 비밀번호", tempData{U: u, Password: pw, Synced: synced == 1})

	case "delete":
		if c.PostForm("confirm") != u.Login {
			s.flash(c, "err", "지우려면 아이디를 똑같이 입력한다.")
			c.Redirect(http.StatusSeeOther, back)
			return
		}
		if u.CloudProjectID != "" || u.CloudUserID != "" {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
			err := s.cl.DeleteStudent(ctx, u.Login)
			cancel()
			if err != nil {
				s.flash(c, "err", "OpenStack 자원을 지우지 못해 포털 계정도 남겨 두었다: "+err.Error())
				c.Redirect(http.StatusSeeOther, back)
				return
			}
		}
		_ = s.st.DeleteUser(c, u.ID)
		audit("삭제", u.Name)
		s.flash(c, "ok", u.Name+"("+u.Login+") 계정을 지웠다. VM·유동 IP 등 OpenStack 자원도 모두 지웠다.")
		c.Redirect(http.StatusSeeOther, "/admin/users?status=all")

	case "sync":
		sync("OpenStack에 다시 맞췄다.")
		c.Redirect(http.StatusSeeOther, back)

	default:
		s.render(c, http.StatusNotFound, "error", "없는 작업", "그런 작업은 없다.")
	}
}

// 운영진이 학생마다 줄 수 있는 범위. 노드 3대(VM용 메모리 약 36GB) 기준이다.
func parseQuota(c *gin.Context) (cloud.Quota, error) {
	get := func(name string, lo, hi int) (int, error) {
		v, err := strconv.Atoi(strings.TrimSpace(c.PostForm(name)))
		if err != nil || v < lo || v > hi {
			return 0, fmt.Errorf("%s는 %d~%d 사이의 정수로 쓴다", quotaLabels[name], lo, hi)
		}
		return v, nil
	}
	var q cloud.Quota
	var err error
	if q.Instances, err = get("instances", 0, 10); err != nil {
		return q, err
	}
	if q.Cores, err = get("cores", 0, 16); err != nil {
		return q, err
	}
	ramGB, err := get("ram_gb", 0, 32)
	if err != nil {
		return q, err
	}
	q.RAMMB = ramGB * 1024
	if q.FloatingIPs, err = get("floating_ips", 0, 5); err != nil {
		return q, err
	}
	return q, nil
}

var quotaLabels = map[string]string{
	"instances": "VM 수", "cores": "vCPU", "ram_gb": "RAM(GB)", "floating_ips": "유동 IP",
}

type auditData struct {
	Rows []db.Audit
	Page int
	More bool
}

func (s *Server) adminAudit(c *gin.Context) {
	const per = 50
	pageNo, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if pageNo < 1 {
		pageNo = 1
	}
	rows, err := s.st.ListAudit(c, db.ListAuditParams{Limit: per + 1, Offset: int64((pageNo - 1) * per)})
	if err != nil {
		s.render(c, http.StatusInternalServerError, "error", "오류", "감사 로그를 읽지 못했다.")
		return
	}
	d := auditData{Page: pageNo, More: len(rows) > per}
	if d.More {
		rows = rows[:per]
	}
	d.Rows = rows
	s.render(c, http.StatusOK, "admin_audit", "감사 로그", d)
}

type orphansData struct {
	Projects []cloud.Project
	Err      string
}

// adminOrphans는 OpenStack에 학생 프로젝트는 있는데 포털에는 없는 계정을 보여 준다(student.sh로 만든 것 등).
func (s *Server) adminOrphans(c *gin.Context) {
	ctx, cancel := cloudCtx(c)
	defer cancel()
	var d orphansData
	ps, err := s.cl.ListStudentProjects(ctx)
	if err != nil {
		d.Err = err.Error()
	}
	for _, p := range ps {
		if _, err := s.st.GetUserByLogin(c, p.Login); err != nil {
			d.Projects = append(d.Projects, p)
		}
	}
	s.render(c, http.StatusOK, "admin_orphans", "포털에 없는 계정", d)
}
