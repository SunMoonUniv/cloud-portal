package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"cloud-portal/internal/auth"
	"cloud-portal/internal/cloud"
	"cloud-portal/internal/store/db"
)

// requireActive는 VM 화면을 사용 중인 학생에게만 연다. 정지·만료된 학생은 포털로도 VM을 다루지 못한다.
func (s *Server) requireActive(c *gin.Context) {
	u, _ := currentUser(c)
	switch {
	case u.Status == "pending":
		c.Redirect(http.StatusSeeOther, "/pending")
	case u.MustChangePassword == 1:
		c.Redirect(http.StatusSeeOther, "/me/password")
	case u.Status != "active" || u.CloudProjectID == "":
		s.render(c, http.StatusForbidden, "error", "쓸 수 없음", "사용 중인 계정만 VM을 다룰 수 있다. 내 정보 화면을 본다.")
	default:
		c.Next()
		return
	}
	c.Abort()
}

var vmNameRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$`)

type vmRow struct {
	cloud.VM
	Label                           string
	Busy                            bool
	IPPending                       bool
	CanStart, CanStop, CanReboot    bool
	CanAttach, CanDetach, CanDelete bool
}

type flavorRow struct {
	cloud.Flavor
	Fits bool // 남은 할당량으로 만들 수 있는지
}

type vmsData struct {
	CSRF           string
	VMs            []vmRow
	Flavors        []flavorRow
	Usage          cloud.Usage
	Quota          cloud.Quota
	KeyFingerprint string
	Err            string
	FormName       string
	FormFlavor     string
	User           string
}

var taskLabels = map[string]string{
	"powering-on": "켜는 중", "powering-off": "끄는 중", "rebooting": "다시 시작하는 중",
	"reboot_pending": "다시 시작하는 중", "reboot_started": "다시 시작하는 중", "deleting": "지우는 중",
	"scheduling": "만드는 중", "networking": "만드는 중", "block_device_mapping": "만드는 중", "spawning": "만드는 중",
}

var vmStatusLabels = map[string]string{
	"BUILD": "만드는 중", "ACTIVE": "켜짐", "SHUTOFF": "꺼짐", "REBOOT": "다시 시작하는 중",
	"HARD_REBOOT": "다시 시작하는 중", "ERROR": "오류", "DELETED": "지워짐",
}

func (s *Server) row(vm cloud.VM) vmRow {
	r := vmRow{VM: vm}
	r.Busy = vm.TaskState != "" || vm.Status == "BUILD" || strings.HasSuffix(vm.Status, "REBOOT")
	if l, ok := taskLabels[vm.TaskState]; ok {
		r.Label = l
	} else if l, ok := vmStatusLabels[vm.Status]; ok {
		r.Label = l
	} else {
		r.Label = vm.Status
	}
	_, r.IPPending = s.autoIP.Load(vm.ID)
	idle := !r.Busy
	r.CanStart = idle && vm.Status == "SHUTOFF"
	r.CanStop = idle && vm.Status == "ACTIVE"
	r.CanReboot = r.CanStop
	r.CanAttach = idle && !r.IPPending && vm.FloatingIP == "" && (vm.Status == "ACTIVE" || vm.Status == "SHUTOFF")
	r.CanDetach = idle && vm.FloatingIP != ""
	r.CanDelete = vm.TaskState != "deleting"
	return r
}

// vmView는 VM 화면과 SSE 조각이 같이 쓰는 값을 모은다.
func (s *Server) vmView(ctx context.Context, u db.User, csrf string) vmsData {
	d := vmsData{
		CSRF: csrf, User: u.Login, KeyFingerprint: auth.SSHKeyFingerprint(u.SshPublicKey),
		Quota: cloud.Quota{
			Instances: int(u.QuotaInstances), Cores: int(u.QuotaCores), RAMMB: int(u.QuotaRamMb), FloatingIPs: int(u.QuotaFloatingIps),
		},
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	vms, err := s.cl.ListVMs(ctx, u.CloudProjectID)
	if err != nil {
		s.log.Warn("VM 목록", "login", u.Login, "err", err)
		d.Err = "VM 목록을 가져오지 못했다. 잠시 뒤 새로 고친다."
		return d
	}
	for _, vm := range vms {
		d.VMs = append(d.VMs, s.row(vm))
	}
	d.Usage, _ = s.cl.Usage(ctx, u.CloudProjectID)
	flavors, _ := s.cl.Flavors(ctx)
	for _, f := range flavors {
		d.Flavors = append(d.Flavors, flavorRow{Flavor: f, Fits: d.Usage.Instances < d.Quota.Instances &&
			d.Usage.Cores+f.VCPUs <= d.Quota.Cores && d.Usage.RAMMB+f.RAMMB <= d.Quota.RAMMB})
	}
	return d
}

func (s *Server) vmsPage(c *gin.Context) {
	u, _ := currentUser(c)
	d := s.vmView(c.Request.Context(), u, c.GetString("csrf"))
	s.render(c, http.StatusOK, "vms", "내 VM", d)
}

// vmsEvents는 VM 화면이 연결하는 SSE다. 목록이 바뀔 때마다 조각을 보낸다(최대 15분, 끊기면 브라우저가 다시 잇는다).
func (s *Server) vmsEvents(c *gin.Context) {
	u, _ := currentUser(c)
	csrf := c.GetString("csrf")
	h := c.Writer.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	c.Writer.Flush()

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Minute)
	defer cancel()
	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()
	last, quiet := "", 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		html, err := s.fragment("vms", "vmlist", s.vmView(ctx, u, csrf))
		if err != nil {
			return
		}
		if html == last {
			// 바뀐 것이 없어도 20초마다 한 번은 보내 연결이 살아 있게 한다.
			if quiet++; quiet < 5 {
				continue
			}
			fmt.Fprint(c.Writer, ": keep-alive\n\n")
			c.Writer.Flush()
			quiet = 0
			continue
		}
		last, quiet = html, 0
		fmt.Fprint(c.Writer, "event: vms\n")
		for _, line := range strings.Split(html, "\n") {
			fmt.Fprintf(c.Writer, "data: %s\n", line)
		}
		fmt.Fprint(c.Writer, "\n")
		c.Writer.Flush()
	}
}

func (s *Server) createVM(c *gin.Context) {
	u, _ := currentUser(c)
	name := strings.ToLower(strings.TrimSpace(c.PostForm("name")))
	flavor := c.PostForm("flavor")
	d := s.vmView(c.Request.Context(), u, c.GetString("csrf"))
	d.FormName, d.FormFlavor = name, flavor
	fail := func(status int, msg string) { s.renderErr(c, status, "vms", "내 VM", msg, d) }

	if u.SshPublicKey == "" {
		fail(http.StatusBadRequest, "먼저 SSH 공개 키를 등록한다.")
		return
	}
	if !vmNameRule.MatchString(name) {
		fail(http.StatusBadRequest, "VM 이름은 영문 소문자·숫자·하이픈(-) 1~30자로 쓴다(예: web1).")
		return
	}
	known := false
	for _, f := range d.Flavors {
		known = known || f.Name == flavor
	}
	if !known {
		fail(http.StatusBadRequest, "크기를 고른다.")
		return
	}
	for _, vm := range d.VMs {
		if vm.Name == name {
			fail(http.StatusConflict, "같은 이름의 VM이 이미 있다.")
			return
		}
	}
	ctx, cancel := cloudCtx(c)
	defer cancel()
	vm, err := s.cl.CreateVM(ctx, u.CloudProjectID, cloud.VMRequest{Name: name, Flavor: flavor, SSHKey: u.SshPublicKey})
	if errors.Is(err, cloud.ErrQuota) {
		fail(http.StatusConflict, "할당량이 모자라 만들 수 없다. 쓰지 않는 VM을 지우거나 운영진에게 늘려 달라고 한다.")
		return
	}
	if err != nil {
		s.log.Warn("VM 만들기", "login", u.Login, "err", err)
		fail(http.StatusBadGateway, "VM을 만들지 못했다. 잠시 뒤 다시 한다.")
		return
	}
	s.st.Audit(c, u.Login, "VM 만들기", u.Login, name+" "+flavor)
	s.attachWhenReady(u.Login, u.CloudProjectID, vm.ID)
	s.flash(c, "ok", name+" VM을 만들고 있다. 1~2분 뒤 켜지면 유동 IP가 저절로 붙는다.")
	c.Redirect(http.StatusSeeOther, "/me/vms")
}

// attachWhenReady는 VM이 켜지면 유동 IP를 붙인다. 할당량이 모자라면 붙이지 않고 그대로 둔다
// (학생이 다른 VM의 유동 IP를 떼고 붙이면 된다).
func (s *Server) attachWhenReady(login, projectID, vmID string) {
	s.autoIP.Store(vmID, true)
	go func() {
		defer s.autoIP.Delete(vmID)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		if err := s.cl.WaitActive(ctx, projectID, vmID); err != nil {
			s.log.Warn("VM이 켜지지 않았다", "login", login, "vm", vmID, "err", err)
			return
		}
		ip, err := s.cl.AttachFloatingIP(ctx, projectID, vmID)
		switch {
		case errors.Is(err, cloud.ErrQuota):
			s.log.Info("유동 IP 할당량이 차서 붙이지 않았다", "login", login, "vm", vmID)
		case err != nil:
			s.log.Warn("유동 IP 붙이기", "login", login, "vm", vmID, "err", err)
		default:
			s.log.Info("유동 IP를 붙였다", "login", login, "vm", vmID, "ip", ip)
		}
	}()
}

// findVM은 학생 프로젝트에서 VM을 찾는다. 다른 학생의 VM ID는 여기서 걸러진다.
func (s *Server) findVM(c *gin.Context, u db.User) (cloud.VM, bool) {
	ctx, cancel := cloudCtx(c)
	defer cancel()
	vms, err := s.cl.ListVMs(ctx, u.CloudProjectID)
	if err == nil {
		for _, vm := range vms {
			if vm.ID == c.Param("id") {
				return vm, true
			}
		}
	}
	s.flash(c, "err", "그 VM을 찾지 못했다.")
	c.Redirect(http.StatusSeeOther, "/me/vms")
	return cloud.VM{}, false
}

// 작업 이름과 시작했을 때 알림. 이름 뒤 조사가 어색하지 않게 "… VM을"로 쓴다.
var vmActions = map[string]struct{ Label, Started string }{
	"start":     {"켜기", "VM을 켜고 있다."},
	"stop":      {"끄기", "VM을 끄고 있다."},
	"reboot":    {"다시 시작", "VM을 다시 시작하고 있다."},
	"attach-ip": {"유동 IP 붙이기", ""},
	"detach-ip": {"유동 IP 떼기", "VM의 유동 IP를 뗐다. 이제 다른 VM에 붙일 수 있다."},
}

func (s *Server) vmAction(c *gin.Context) {
	u, _ := currentUser(c)
	action := c.Param("action")
	act, ok := vmActions[action]
	if !ok {
		s.render(c, http.StatusNotFound, "error", "없는 작업", "그런 작업은 없다.")
		return
	}
	vm, ok := s.findVM(c, u)
	if !ok {
		return
	}
	ctx, cancel := cloudCtx(c)
	defer cancel()
	var err error
	msg := vm.Name + " " + act.Started
	switch action {
	case "attach-ip":
		var ip string
		if ip, err = s.cl.AttachFloatingIP(ctx, u.CloudProjectID, vm.ID); err == nil {
			msg = vm.Name + " VM에 유동 IP를 붙였다: " + ip
		}
	case "detach-ip":
		err = s.cl.DetachFloatingIP(ctx, u.CloudProjectID, vm.ID)
	default:
		err = s.cl.VMAction(ctx, u.CloudProjectID, vm.ID, action)
	}
	switch {
	case errors.Is(err, cloud.ErrQuota):
		s.flash(c, "err", "유동 IP 할당량이 다 찼다. 다른 VM의 유동 IP를 먼저 뗀다.")
	case errors.Is(err, cloud.ErrState):
		s.flash(c, "err", vm.Name+" VM은 지금 상태에서 "+act.Label+" 작업을 받지 않는다. 잠시 뒤 다시 한다.")
	case err != nil:
		s.log.Warn("VM 작업", "login", u.Login, "vm", vm.ID, "action", action, "err", err)
		s.flash(c, "err", vm.Name+" VM: "+act.Label+" 작업을 하지 못했다.")
	default:
		s.st.Audit(c, u.Login, "VM "+act.Label, u.Login, vm.Name)
		s.flash(c, "ok", msg)
	}
	c.Redirect(http.StatusSeeOther, "/me/vms")
}

func (s *Server) deleteVMForm(c *gin.Context) {
	u, _ := currentUser(c)
	if vm, ok := s.findVM(c, u); ok {
		s.render(c, http.StatusOK, "vm_delete", "VM 지우기", vm)
	}
}

func (s *Server) deleteVM(c *gin.Context) {
	u, _ := currentUser(c)
	vm, ok := s.findVM(c, u)
	if !ok {
		return
	}
	ctx, cancel := cloudCtx(c)
	defer cancel()
	if err := s.cl.DeleteVM(ctx, u.CloudProjectID, vm.ID); err != nil {
		s.log.Warn("VM 지우기", "login", u.Login, "vm", vm.ID, "err", err)
		s.flash(c, "err", vm.Name+" VM을 지우지 못했다. 잠시 뒤 다시 한다.")
	} else {
		s.st.Audit(c, u.Login, "VM 지우기", u.Login, vm.Name)
		s.flash(c, "ok", vm.Name+" VM을 지우고 있다. 유동 IP는 돌려줬다.")
	}
	c.Redirect(http.StatusSeeOther, "/me/vms")
}

type keyData struct {
	Fingerprint string
	Key         string
}

func (s *Server) keyPage(c *gin.Context) {
	u, _ := currentUser(c)
	s.render(c, http.StatusOK, "key", "SSH 키", keyData{Fingerprint: auth.SSHKeyFingerprint(u.SshPublicKey)})
}

func (s *Server) saveKey(c *gin.Context) {
	u, _ := currentUser(c)
	line, fp, err := auth.NormalizeSSHKey(c.PostForm("key"))
	if err != nil {
		s.renderErr(c, http.StatusBadRequest, "key", "SSH 키", err.Error(),
			keyData{Fingerprint: auth.SSHKeyFingerprint(u.SshPublicKey), Key: c.PostForm("key")})
		return
	}
	_ = s.st.SetSSHKey(c, db.SetSSHKeyParams{SshPublicKey: line, UpdatedAt: time.Now().Unix(), ID: u.ID})
	s.st.Audit(c, u.Login, "SSH 키 등록", u.Login, fp)
	s.flash(c, "ok", "SSH 공개 키를 등록했다("+fp+"). 이제부터 만드는 VM에 들어간다.")
	c.Redirect(http.StatusSeeOther, "/me/vms")
}

// newKey는 키 쌍을 새로 만들어 공개 키는 저장하고, 개인 키는 파일로 한 번만 내려 준다.
func (s *Server) newKey(c *gin.Context) {
	u, _ := currentUser(c)
	priv, pub, err := auth.GenerateSSHKey(u.Login + "@student-cloud")
	if err != nil {
		s.flash(c, "err", "키를 만들지 못했다.")
		c.Redirect(http.StatusSeeOther, "/me/key")
		return
	}
	_ = s.st.SetSSHKey(c, db.SetSSHKeyParams{SshPublicKey: pub, UpdatedAt: time.Now().Unix(), ID: u.ID})
	s.st.Audit(c, u.Login, "SSH 키 새로 만들기", u.Login, auth.SSHKeyFingerprint(pub))
	s.flash(c, "ok", "새 키를 만들었다. 내려받은 파일(student-cloud-key)을 잃어버리면 다시 받을 수 없다.")
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", `attachment; filename="student-cloud-key"`)
	c.Data(http.StatusOK, "application/octet-stream", priv)
}
