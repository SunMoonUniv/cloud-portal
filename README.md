# cloud-portal

선문대 학생 클라우드(OpenStack) 포털이다. 학생이 가입을 신청하고, 운영진이 승인하면 OpenStack 계정, 프로젝트, 할당량, 보안 그룹을 자동으로 만든다.
학생은 SSH 키 등록, VM 만들기·켜기·끄기·다시 시작·지우기, 유동 IP를 포털에서 하고, VM 안의 작업은 SSH로 직접 한다. 웹 콘솔(Horizon, http://192.168.0.205)은 보안 그룹에서 포트를 열 때처럼 포털에 없는 기능에만 쓴다.

- 주소: **http://192.168.0.251** (node01, 80번). 실습실 LAN 전용 MVP-0이고 HTTP다.
- Go 1.27, Gin, html/template + htmx(승인 대기 화면만 SSE), SQLite(modernc, CGO 없음)
- OpenStack 규칙은 `~/cloud-ops/scripts/student.sh`와 같다. 한쪽을 바꾸면 다른 쪽도 같이 바꾼다.
- 저장소: https://github.com/SunMoonUniv/cloud-portal (공개). 배포는 https://github.com/SunMoonUniv/cloud-ops 의 `playbooks/portal.yml`이 맡는다. 공개 저장소이니 DB 파일과 `/etc/cloud-portal/*.env`는 넣지 않는다.

## 흐름

1. 학생이 `/signup`에서 학번·이름·비밀번호로 신청한다. 같은 IP는 1시간에 5번까지, 승인 대기는 50명까지 받는다.
2. 운영진이 `/admin`에서 승인하면 되맞추기가 바로 돌아 OpenStack 계정을 만든다.
   - 프로젝트 `student-<아이디>`(태그 `student`), 사용자, member 역할
   - 할당량: VM 2, vCPU 2, RAM 4GB, 유동 IP 1, 네트워크·라우터 0
   - 기본 보안 그룹: 실습실 LAN(유동 IP 범위 제외)에서 22와 ping
3. 학생은 승인 대기 화면에서 바로(SSE) 또는 다음 로그인 때 웹 콘솔 비밀번호를 맞춘다. 웹 콘솔은 포털과 같은 비밀번호를 쓴다.
4. 학생은 `/me/key`에서 SSH 키를 등록하고(붙여 넣기 또는 새로 만들어 개인 키를 한 번 내려받기), `/me/vms`에서 VM을 만든다.
   VM이 켜지면 유동 IP가 저절로 붙고, 목록은 SSE로 저절로 바뀐다.
5. 정지·만료되면 Keystone 사용자만 끈다(웹 콘솔 로그인 불가). 포털의 VM 화면도 막는다. VM은 그대로 둔다.

### 비밀번호

- 포털은 argon2id 해시만 저장한다. 평문은 저장하지 않는다.
- 학생이 비밀번호를 입력하는 순간에만 Keystone 비밀번호를 같은 값으로 넣는다. 그 순간은 승인 뒤 확인, 로그인, 비밀번호 변경, 운영진의 임시 비밀번호 발급이다.
- 학생 Keystone 사용자에는 `lock_password` 옵션을 켠다. 그래서 웹 콘솔의 비밀번호 바꾸기는 "Password is locked."로 거부되고, 포털에서만 바꿀 수 있다.
  - Keystone 정책(`identity:change_password`)으로는 막을 수 없다. 비밀번호 변경 API가 정책을 검사하지 않는다(`unenforced_api`).
  - 화면에서 메뉴 자체는 보인다.

### VM 화면

- 포털 계정(`cloud-portal`)이 각 학생 프로젝트의 member 역할을 갖고, 그 프로젝트로 범위를 둔 토큰으로 VM을 다룬다. 그래서 할당량은 OpenStack이 지키고, 다른 학생의 VM은 보이지 않는다. 역할은 되맞추기가 넣는다.
- VM은 이미지 `ubuntu-24.04`, 네트워크 `student-net`, 보안 그룹 `default`로만 만든다. 크기는 이름이 `s.`로 시작하는 공개 플레이버 중에서 고른다. 이름은 영문 소문자·숫자·하이픈 1~30자이고 프로젝트 안에서 겹치지 않게 한다.
- SSH 키는 Nova 키 페어가 아니라 cloud-init(`ssh_authorized_keys`)으로 넣는다. 포털은 공개 키만 저장한다(`users.ssh_public_key`). "새로 만들기"는 ed25519 키 쌍을 만들어 개인 키를 한 번 내려 주고 저장하지 않는다. 키를 바꾸면 앞으로 만드는 VM에만 들어간다.
- 유동 IP: VM을 만들면 켜질 때까지 기다렸다가 하나 붙인다(할당량이 차 있으면 붙이지 않는다). 떼면 돌려줘서 다른 VM에 붙일 수 있다. 목록의 유동 IP는 Neutron에서 직접 읽는다(Nova 주소 정보는 몇 초 늦다).
- Nova는 만드는 중인 VM을 API 할당량 검사에서 다 세지 않을 때가 있다. 그래서 빠르게 연달아 만들면 넘친 VM이 오류(Quota exceeded)로 남을 수 있고, 목록에 이유와 "지운다" 안내가 나온다.

### 되맞추기

포털 DB가 기준이다. 5분마다, 그리고 운영진 작업 직후에 돈다.
- 사용 중인 계정은 프로젝트, 사용자, 할당량, 보안 그룹을 맞추고 사용자를 켠다.
- 정지·만료된 계정은 사용자를 끈다.
- 만료일이 지난 계정은 만료로 바꾼다.

실패하면 DB에 오류를 남기고, 운영진 화면에 "오류"로 보인다. 다음 차례에 다시 시도한다.

OpenStack에 학생 프로젝트는 있는데 포털에는 없는 계정(student.sh로 만든 것 등)은 `/admin/orphans`에 보여 주기만 한다. 같은 이름의 Keystone 사용자가 학생 프로젝트에 속하지 않으면(admin, 서비스 계정) 아무것도 만들거나 지우지 않고 멈춘다.

## 구조

| 경로 | 내용 |
| --- | --- |
| `cmd/cloud-portal` | `serve`, `admin add <아이디> <이름>`, `admin passwd <아이디>`, `reconcile` |
| `internal/store` | SQLite 열기·마이그레이션. 쿼리는 `sql/queries.sql` → sqlc가 `internal/store/db`에 만든다 |
| `internal/auth` | argon2id, 아이디·비밀번호 규칙, 세션 토큰, 횟수 제한 |
| `internal/cloud` | OpenStack(gophercloud v2): 계정(`openstack.go`), VM(`vms.go`), 처음 쓸 때 접속하는 `Lazy`, 시험용 `Fake` |
| `internal/reconcile` | 되맞추기 |
| `internal/web` | 라우트·화면. `templates/`, `static/`(htmx 2.0.11, htmx-ext-sse 2.2.4를 npm 무결성 값으로 확인해 넣음) |
| `sql/` | `schema.sql`(1단계), `002_ssh_key.sql`(2단계), `queries.sql`. 스키마를 바꾸면 파일을 하나 더하고 `sqlc.yaml`, `sql/embed.go`, `internal/store/store.go`의 migrations에 넣는다 |

## 설정(환경 변수)

| 이름 | 기본값 | 뜻 |
| --- | --- | --- |
| `PORTAL_LISTEN` | `127.0.0.1:8080` | 듣는 주소. 배포에서는 `192.168.0.251:80` |
| `PORTAL_DB` | `portal.db` | SQLite 파일 |
| `PORTAL_CONSOLE_URL` | `http://192.168.0.205` | 웹 콘솔 주소 |
| `PORTAL_CLOUD` | `openstack` | `fake`면 OpenStack 없이(개발용) |
| `PORTAL_RECONCILE_INTERVAL` | `5m` | 되맞추기 간격 |
| `PORTAL_PENDING_MAX`, `PORTAL_SIGNUP_PER_HOUR` | `50`, `5` | 대기 상한, IP별 1시간 신청 수 |
| `OS_AUTH_URL`, `OS_USERNAME`, `OS_PASSWORD`, `OS_PROJECT_NAME`, `OS_USER_DOMAIN_NAME`, `OS_REGION_NAME`, `OS_INTERFACE` | | Keystone 접속(배포에서는 포털 전용 사용자 `cloud-portal`) |

## 개발

```bash
export PATH=$HOME/.local/go/bin:$HOME/.local/bin:$PATH
cd ~/cloud-portal
go test ./...                               # 단위·화면 흐름 시험(가짜 OpenStack)
sqlc generate                               # sql/queries.sql을 고쳤을 때
echo 'devpass123' | PORTAL_DB=dev.db go run ./cmd/cloud-portal admin add dev 개발자
PORTAL_DB=dev.db PORTAL_CLOUD=fake go run ./cmd/cloud-portal serve   # http://127.0.0.1:8080
```

실제 OpenStack으로 시험하려면 node01에서 아래를 돌린다. 시험 계정 `it-…`를 만들고 지운다.

```bash
set -a; . /etc/kolla/admin-openrc.sh; set +a
PORTAL_IT=1 go test ./internal/cloud/ -v      # 계정(5초), VM(약 1분)
```

## 배포와 운영 (node01)

배포는 cloud-ops가 맡는다. 시험, 빌드, 설치, systemd 재시작까지 한다.

```bash
cd ~/cloud-ops && source ~/kolla-venv/bin/activate
ansible-playbook playbooks/portal.yml
```

- 서비스: `cloud-portal.service`(사용자 `cloud-portal`, 80번 권한만), 실행 파일 `/usr/local/bin/cloud-portal`
- 설정: `/etc/cloud-portal/portal.env`, Keystone 비밀번호 `/etc/cloud-portal/keystone.env`(둘 다 root 600)
- DB: `/var/lib/cloud-portal/portal.db`. 백업은 이 파일을 복사한다(서비스를 멈추거나 `sqlite3 .backup`)
- 로그: `journalctl -u cloud-portal`

첫 운영진 계정은 서버에서 만든다. DB 파일 주인이 바뀌지 않게 **반드시 `-u cloud-portal`로** 돌린다.

```bash
sudo -u cloud-portal env PORTAL_DB=/var/lib/cloud-portal/portal.db /usr/local/bin/cloud-portal admin add <아이디> <이름>
```

운영진 비밀번호를 잊었으면 같은 방법으로 `admin passwd <아이디>`를 쓴다.

## 아직 없는 것

- HTTPS와 학교 계정 로그인(MVP-1)
- 메일 알림. 승인·임시 비밀번호는 운영진이 직접 알려 준다
- 웹 콘솔의 "비밀번호 바꾸기" 메뉴 숨기기. 지금은 메뉴는 보이고, 누르면 거부된다
- 운영진 계정 지우기·여러 운영진 관리 화면. 운영진 계정은 서버 명령으로만 만든다
