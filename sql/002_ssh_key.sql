-- 2단계(2026-11-01): 학생이 등록한 SSH 공개 키. VM을 만들 때 cloud-init으로 넣는다.
ALTER TABLE users ADD COLUMN ssh_public_key TEXT NOT NULL DEFAULT '';
