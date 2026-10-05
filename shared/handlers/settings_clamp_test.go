package handlers

import (
	"net/http"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestUpdateSettingsClampsNumericValues 锁定 S-04：管理员改设置时数值必须被钳制，
// 避免写入超大 password_min_length 等导致全体用户无法设置口令（功能 DoS）。
func TestUpdateSettingsClampsNumericValues(t *testing.T) {
	r, database := newTestServer(t)
	token := setupAdmin(t, r)

	code, resp := doJSON(t, r, http.MethodPut, "/api/settings", token, map[string]any{
		"port":                     -5,
		"password_min_length":      100000,
		"recycle_days":             2147483647,
		"password_require_complex": true,
	})
	if code != http.StatusOK {
		t.Fatalf("更新设置: code=%d resp=%v", code, resp)
	}

	if got := db.GetMeta(database, "password_min_length"); got != "128" {
		t.Fatalf("password_min_length 未被钳制，实际 %q（应为 128）", got)
	}
	if got := db.GetMeta(database, "recycle_days"); got != "3650" {
		t.Fatalf("recycle_days 未被钳制，实际 %q（应为 3650）", got)
	}
	if got := db.GetMeta(database, "smtp_port"); got != "465" {
		t.Fatalf("非法 smtp_port 应回退默认 465，实际 %q", got)
	}
}

// TestCreateUserRejectsReservedUsername 锁定 S-01 的纵深防御：管理员不得创建保留名账号。
func TestCreateUserRejectsReservedUsername(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	for _, name := range []string{"admin", "root", "SuperAdmin", "SYSTEM"} {
		code, _ := doJSON(t, r, http.MethodPost, "/api/users", token, map[string]any{
			"username": name, "password": "Passw0rd!", "email": name + "@example.com", "role": "admin",
		})
		if code == http.StatusOK {
			t.Fatalf("保留用户名 %q 竟然创建成功", name)
		}
	}
}

// TestUpdateUserRejectsReservedUsernameRename 锁定 S-01 的第二条路径：不得把用户改名为保留名。
func TestUpdateUserRejectsReservedUsernameRename(t *testing.T) {
	r, _ := newTestServer(t)
	token := setupAdmin(t, r)

	// 先建一个普通用户。
	code, _ := doJSON(t, r, http.MethodPost, "/api/users", token, map[string]any{
		"username": "alice", "password": "Passw0rd!", "email": "alice@example.com", "role": "admin",
	})
	if code != http.StatusOK {
		t.Fatalf("前置创建 alice 失败: code=%d", code)
	}

	// 取出 alice 的 id。
	var id int64
	// 复用 GET /api/users
	code, resp := doJSON(t, r, http.MethodGet, "/api/users", token, nil)
	if code != http.StatusOK {
		t.Fatalf("列出用户: code=%d", code)
	}
	if users, ok := resp["users"].([]any); ok {
		for _, u := range users {
			if m, ok := u.(map[string]any); ok {
				if m["username"] == "alice" {
					if f, ok := m["id"].(float64); ok {
						id = int64(f)
					}
				}
			}
		}
	}
	if id == 0 {
		t.Fatalf("未找到 alice 的 id, resp=%v", resp)
	}

	code, _ = doJSON(t, r, http.MethodPost, "/api/users/update?id="+itoa(id), token, map[string]any{
		"username": "admin", "role": "admin",
	})
	if code == http.StatusOK {
		t.Fatalf("把用户改名为保留用户名 admin 竟然成功")
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
