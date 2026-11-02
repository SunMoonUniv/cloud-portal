// cloud-portal은 학생 클라우드 포털이다. 설정은 환경 변수로 받는다(README 참고).
//
//	cloud-portal serve                      포털을 띄운다
//	cloud-portal admin add <아이디> <이름>   운영진 계정을 만든다(비밀번호는 입력받는다)
//	cloud-portal admin passwd <아이디>       포털 비밀번호를 바꾼다(운영진이 잠겼을 때)
//	cloud-portal reconcile                  OpenStack 되맞추기를 한 번만 돌린다
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"cloud-portal/internal/auth"
	"cloud-portal/internal/cloud"
	"cloud-portal/internal/reconcile"
	"cloud-portal/internal/store"
	"cloud-portal/internal/store/db"
	"cloud-portal/internal/web"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(log)
	case "admin":
		err = admin(os.Args[2:])
	case "reconcile":
		err = reconcileOnce(log)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `사용: cloud-portal serve | admin add <아이디> <이름> | admin passwd <아이디> | reconcile`)
	os.Exit(2)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func openStore() (*store.Store, error) {
	return store.Open(env("PORTAL_DB", "portal.db"))
}

// openCloud는 PORTAL_CLOUD=fake면 메모리 가짜를, 아니면 OpenStack을 돌려준다.
// serve는 처음 쓸 때 접속하고(lazy), 한 번만 도는 명령은 바로 접속해 오류를 보여 준다.
func openCloud(ctx context.Context, lazy bool) (cloud.Cloud, error) {
	if env("PORTAL_CLOUD", "openstack") == "fake" {
		return cloud.NewFake(), nil
	}
	if lazy {
		return &cloud.Lazy{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return cloud.NewOpenStack(ctx)
}

func serve(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	cl, err := openCloud(ctx, true)
	if err != nil {
		return err
	}
	interval, err := time.ParseDuration(env("PORTAL_RECONCILE_INTERVAL", "5m"))
	if err != nil {
		return fmt.Errorf("PORTAL_RECONCILE_INTERVAL: %w", err)
	}
	rec := &reconcile.Reconciler{Store: st, Cloud: cl, Log: log, Interval: interval}
	srv, err := web.New(web.Config{
		ConsoleURL:    env("PORTAL_CONSOLE_URL", "http://192.168.0.205"),
		PendingMax:    envInt("PORTAL_PENDING_MAX", 50),
		SignupPerHour: envInt("PORTAL_SIGNUP_PER_HOUR", 5),
		SessionTTL:    12 * time.Hour,
	}, st, cl, rec, log)
	if err != nil {
		return err
	}
	go rec.Run(ctx)

	addr := env("PORTAL_LISTEN", "127.0.0.1:8080")
	hs := &http.Server{
		Addr: addr, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		// WriteTimeout은 두지 않는다. 승인 대기 화면의 SSE가 오래 열려 있다(최대 30분).
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("포털 시작", "listen", addr, "cloud", env("PORTAL_CLOUD", "openstack"))
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("포털 멈춤")
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func reconcileOnce(log *slog.Logger) error {
	ctx := context.Background()
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	cl, err := openCloud(ctx, false)
	if err != nil {
		return err
	}
	return (&reconcile.Reconciler{Store: st, Cloud: cl, Log: log}).Once(ctx)
}

func admin(args []string) error {
	if len(args) < 2 {
		usage()
	}
	ctx := context.Background()
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	login := args[1]

	switch {
	case args[0] == "add" && len(args) == 3:
		name, ok := auth.CleanName(args[2])
		if !auth.ValidLogin(login) || !ok {
			return errors.New("아이디는 영문·숫자·._- 3~32자, 이름은 1~40자로 쓴다")
		}
		if _, err := st.GetUserByLogin(ctx, login); err == nil {
			return fmt.Errorf("%s는 이미 있다", login)
		}
		pw, err := readPassword()
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if _, err := st.CreateUser(ctx, db.CreateUserParams{
			Login: login, Name: name, PasswordHash: hash, Role: "admin", Status: "active", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		st.Audit(ctx, "cli", "운영진 추가", login, name)
		fmt.Printf("운영진 %s(%s)를 만들었다.\n", login, name)

	case args[0] == "passwd" && len(args) == 2:
		u, err := st.GetUserByLogin(ctx, login)
		if err != nil {
			return fmt.Errorf("%s가 없다", login)
		}
		pw, err := readPassword()
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if err := st.SetPassword(ctx, db.SetPasswordParams{PasswordHash: hash, UpdatedAt: now, ID: u.ID}); err != nil {
			return err
		}
		// 학생이면 웹 콘솔 비밀번호는 다음 로그인 때 맞춘다.
		_ = st.SetCloudPasswordSynced(ctx, db.SetCloudPasswordSyncedParams{CloudPasswordSynced: 0, UpdatedAt: now, ID: u.ID})
		_ = st.DeleteUserSessions(ctx, u.ID)
		st.Audit(ctx, "cli", "비밀번호 재설정", login, "")
		fmt.Printf("%s의 비밀번호를 바꿨다.\n", login)

	default:
		usage()
	}
	return nil
}

// readPassword는 터미널이면 두 번 입력받고, 아니면 표준 입력의 첫 줄을 쓴다(스크립트용).
func readPassword() (string, error) {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "비밀번호: ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "비밀번호 다시: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("두 비밀번호가 다르다")
		}
		pw = string(a)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("표준 입력에서 비밀번호를 읽지 못했다")
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	if !auth.ValidPassword(pw) {
		return "", fmt.Errorf("비밀번호는 %d~%d자로 쓴다", auth.MinPasswordLen, auth.MaxPasswordLen)
	}
	return pw, nil
}
