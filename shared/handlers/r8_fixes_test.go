package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// R8-04 回归测试（第八轮修复）：系统配置导入路径必须钳制 smtp_port。
//
// 原缺陷：importableMetaKeys 含 smtp_port，但 handleImportSettings 只对
// password_min_length/recycle_days 做钳制，端口可被写成 0/负数/超范围值，
// 使 LoadSMTPConfig 解析失败、SMTP 静默失效（界面仍显示"已启用"）。
func TestR8ImportSettingsClampsSMTPPort(t *testing.T) {
	r, database := newTestServer(t)
	doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	})
	_, sa := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	})
	tok, _ := sa["token"].(string)
	if tok == "" {
		t.Fatal("登录失败")
	}

	importPort := func(v string) {
		c, resp := doJSON(t, r, http.MethodPost, "/api/settings/import", tok, map[string]any{
			"meta": map[string]string{"smtp_port": v},
		})
		if c != http.StatusOK {
			t.Fatalf("导入 smtp_port=%q 失败: %d %v", v, c, resp["error"])
		}
	}

	for _, v := range []string{"0", "-1", "999999"} {
		importPort(v)
		got := db.GetMeta(database, "smtp_port")
		n, err := strconv.Atoi(got)
		if err != nil || n < 1 || n > 65535 {
			t.Errorf("导入 smtp_port=%q 未钳制，落库值 %q（应在 [1,65535]）", v, got)
		}
	}

	// 非数字应被跳过、保留原值（不产生非法端口）。
	if _, err := database.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES ('smtp_port', '465')`); err != nil {
		t.Fatalf("预置端口失败: %v", err)
	}
	importPort("abc")
	if got := db.GetMeta(database, "smtp_port"); got != "465" {
		t.Errorf("非法端口应跳过并保留原值 465，实际 %q", got)
	}
}

// R8-06 回归测试（第八轮修复）：停用账号登录不得回显"账号已被停用"。
//
// 原缺陷：口令校验通过后返回 403 "账号已被停用"，一次请求即泄露
// "账号存在 + 口令正确 + 状态"。修复后与失败路径一致返回通用 401 文案。
func TestR8DisabledAccountLoginIsIndistinguishable(t *testing.T) {
	r, _ := newTestServer(t)
	doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	})
	_, sa := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	})
	tok, _ := sa["token"].(string)

	if c, resp := doJSON(t, r, http.MethodPost, "/api/users", tok, map[string]any{
		"username": "bob", "password": "BobPasswd1", "email": "bob@x.example", "role": "user",
	}); c != http.StatusOK {
		t.Fatalf("创建 bob 失败: %d %v", c, resp["error"])
	}
	var id int64
	_, users := doJSON(t, r, http.MethodGet, "/api/users", tok, nil)
	for _, u := range users["users"].([]any) {
		m := u.(map[string]any)
		if m["username"] == "bob" {
			id = int64(m["id"].(float64))
		}
	}
	if id == 0 {
		t.Fatal("未找到 bob")
	}
	if c, resp := doJSON(t, r, http.MethodPost, "/api/users/status?id="+strconv.FormatInt(id, 10), tok,
		map[string]any{"status": "disabled"}); c != http.StatusOK {
		t.Fatalf("停用 bob 失败: %d %v", c, resp["error"])
	}

	// 口令正确：必须 401，且文案不得暴露账号状态。
	c, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "bob", "password": "BobPasswd1",
	})
	if c != http.StatusUnauthorized {
		t.Errorf("停用账号登录应返回 401，实际 %d %v", c, resp["error"])
	}
	if msg, _ := resp["error"].(string); strings.Contains(msg, "停用") {
		t.Errorf("登录响应泄露账号状态: %q", msg)
	}

	// 与"口令错误"路径的响应必须完全一致（不可区分）。
	c2, resp2 := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "bob", "password": "WrongPass1",
	})
	if c2 != c || resp2["error"] != resp["error"] {
		t.Errorf("停用账号与口令错误响应不一致：%d/%v vs %d/%v", c, resp["error"], c2, resp2["error"])
	}
}
