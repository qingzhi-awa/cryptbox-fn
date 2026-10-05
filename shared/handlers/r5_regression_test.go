package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qingzhi-awa/cryptbox/shared/auth"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

func nowMillis() int64 { return time.Now().UnixMilli() }

// TestDuplicateUsernameConflictIsNotRetried 锁定 R5-01：用户名重复是**业务冲突**，
// 必须快速返回可判定错误（409），不得被误当作 users.id 主键竞争而重试 64 次后返回 500。
//
// 回归背景：isUniqueConstraintErr 用宽匹配（含泛化的 "constraint failed"），而 SQLite
// 对 users.id 与 users.username 两种冲突都返回 "constraint failed: UNIQUE constraint
// failed: users.<col>"，于是同名冲突被吞进重试路径。并发同名建号必须"一成功 + 一冲突"。
func TestDuplicateUsernameConflictIsNotRetried(t *testing.T) {
	r, database := newTestServer(t)
	token := setupAdmin(t, r)

	const dup = "dup_user"
	var wg sync.WaitGroup
	codes := make([]int, 2)

	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			defer wg.Done()
			code, _ := doJSON(t, r, http.MethodPost, "/api/users", token, map[string]any{
				"username": dup,
				"password": "Passw0rd!",
				"email":    fmt.Sprintf("dup%d@example.com", idx),
				"role":     "user",
			})
			codes[idx] = code
		}(i)
	}
	wg.Wait()

	success, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			success++
		case http.StatusConflict:
			conflict++
		default:
			t.Errorf("出现非预期状态码 %d（期望 200 或 409，500 表明被误判为 id 竞争重试）", c)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("期望一成功一冲突，实际 success=%d conflict=%d codes=%v", success, conflict, codes)
	}

	// 确认库中只有一条同名记录。
	var n int
	if err := database.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ?`, dup).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("期望 1 条同名用户，实际 %d", n)
	}
}

// TestDuplicateUsernameConflictFastFails 直接针对 db 层：同名冲突必须**立即**返回，
// 不得消耗重试预算（用耗时上限间接断言"没有走 64 次随机退避"）。
func TestDuplicateUsernameConflictFastFails(t *testing.T) {
	_, database := newTestServer(t)

	if _, err := db.CreateUserWithNextID(database, "same_name", "$2a$12$x", "user", "a@example.com", "", ""); err != nil {
		t.Fatalf("首次创建应成功: %v", err)
	}
	// 第二次同名：必须返回错误，且不得是"重试次数已用尽"（那意味着被误判为 id 竞争）。
	start := nowMillis()
	_, err := db.CreateUserWithNextID(database, "same_name", "$2a$12$x", "user", "b@example.com", "", "")
	elapsed := nowMillis() - start
	if err == nil {
		t.Fatalf("同名第二次创建应失败")
	}
	if strings.Contains(err.Error(), "重试次数已用尽") {
		t.Fatalf("同名冲突被误判为 id 竞争并耗尽重试: %v", err)
	}
	// 64 次退避至少约数秒；快速失败应在很短时间内完成。
	if elapsed > 1000 {
		t.Fatalf("同名冲突耗时 %dms，疑似仍在重试退避（应快速失败）", elapsed)
	}
}

// TestUpdateMeRejectsReservedUsername 锁定 R5-02：用户自助改名接口也必须拒绝保留名。
func TestUpdateMeRejectsReservedUsername(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	// 建一个普通用户并登录。
	if code, _ := doJSON(t, r, http.MethodPost, "/api/users", token, map[string]any{
		"username": "bob", "password": "Passw0rd!", "email": "bob@example.com", "role": "user",
	}); code != http.StatusOK {
		t.Fatalf("创建 bob 失败")
	}
	// 用 bob 登录拿 token。
	code, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "bob", "password": "Passw0rd!",
	})
	if code != http.StatusOK {
		t.Fatalf("bob 登录失败: code=%d resp=%v", code, resp)
	}
	bobToken, _ := resp["token"].(string)
	if bobToken == "" {
		t.Fatalf("未取得 bob 的 token: %v", resp)
	}

	for _, name := range []string{"admin", "root", "SuperAdmin", "SYSTEM"} {
		code, _ := doJSON(t, r, http.MethodPut, "/api/me", bobToken, map[string]any{"username": name})
		if code == http.StatusOK {
			t.Fatalf("普通用户通过 /api/me 改名为保留名 %q 竟然成功", name)
		}
	}
}

// TestImportSettingsEncryptedPasswordIsIdempotent 锁定 R5-03：导入已是 enc: 前缀的
// 密文时不得二次加密，否则解密出来是字面量 "enc:..."，SMTP 静默失效。
func TestImportSettingsEncryptedPasswordIsIdempotent(t *testing.T) {
	r, database, encKey := newTestServerWithEncKey(t)
	token := setupAdmin(t, r)

	const plain = "ReimportSecret!"
	enc, err := auth.EncryptSMTPPassword(encKey, plain)
	if err != nil {
		t.Fatalf("预加密失败: %v", err)
	}

	code, resp := doJSON(t, r, http.MethodPost, "/api/settings/import", token, map[string]any{
		"meta": map[string]any{"smtp_password": enc},
	})
	if code != http.StatusOK {
		t.Fatalf("导入密文: code=%d resp=%v", code, resp)
	}

	// 落库必须仍是单层密文且能还原出原口令。
	cfg := auth.LoadSMTPConfig(database, encKey)
	if cfg.Password != plain {
		t.Fatalf("二次加密导致口令不可还原：got %q, want %q", cfg.Password, plain)
	}
}
