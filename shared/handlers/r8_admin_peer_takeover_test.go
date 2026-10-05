package handlers

import (
	"net/http"
	"strconv"
	"testing"
)

// R8-01 回归测试（第八轮修复）：同级管理员不得互管。
//
// 原缺陷：auth.CanManageUser("admin","admin") 返回 true，使任一 admin 可经
// POST /api/users/update?id= 改写另一个 admin 的口令（改密还会递增 token_version，
// 把对方所有会话踢下线，正好为接管清场），随后以对方身份登录——横向账号接管。
// 修复后 admin 只能管理普通 user，superadmin 不受限。
//
// 覆盖：
//  1) adminA 改同级 adminB 的口令 → 403；
//  2) 纵深断言：adminA 无法以篡改后的口令登录 adminB，且 adminB 原口令仍有效；
//  3) 反向断言：admin 仍可正常管理普通用户（避免过度收紧）。
func TestR8AdminCannotManagePeerAdmin(t *testing.T) {
	r, _ := newTestServer(t)

	if c, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	}); c != http.StatusOK {
		t.Fatalf("setup 超管失败: %d", c)
	}
	_, sa := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	})
	saTok, _ := sa["token"].(string)

	mk := func(name, pass, role string) {
		if c, resp := doJSON(t, r, http.MethodPost, "/api/users", saTok, map[string]any{
			"username": name, "password": pass, "email": name + "@mail.example", "role": role,
		}); c != http.StatusOK {
			t.Fatalf("创建 %s 失败: %d %v", name, c, resp["error"])
		}
	}
	mk("adminA", "AdminApass1", "admin")
	mk("adminB", "AdminBpass1", "admin")
	mk("bob", "BobPasswd1", "user")

	idOf := func(name string) int64 {
		_, users := doJSON(t, r, http.MethodGet, "/api/users", saTok, nil)
		for _, u := range users["users"].([]any) {
			m := u.(map[string]any)
			if m["username"] == name {
				return int64(m["id"].(float64))
			}
		}
		return 0
	}
	idB, idBob := idOf("adminB"), idOf("bob")
	if idB == 0 || idBob == 0 {
		t.Fatalf("未找到目标用户: adminB=%d bob=%d", idB, idBob)
	}

	_, a := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "adminA", "password": "AdminApass1",
	})
	tokA, _ := a["token"].(string)
	if tokA == "" {
		t.Fatal("adminA 登录失败")
	}

	// —— 1) 核心断言：adminA 改同级 adminB 的口令必须被拒绝（403）——
	c, resp := doJSON(t, r, http.MethodPost, "/api/users/update?id="+strconv.FormatInt(idB, 10), tokA,
		map[string]any{"password": "Hijacked123"})
	if c != http.StatusForbidden {
		t.Errorf("adminA 修改同级 adminB 口令未被拒绝：HTTP %d %v", c, resp["error"])
	}

	// —— 2) 纵深断言：篡改口令不得生效，原口令仍可用 ——
	if c2, _ := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "adminB", "password": "Hijacked123",
	}); c2 == http.StatusOK {
		t.Errorf("adminA 已成功接管 adminB：以篡改口令登录返回 200")
	}
	if c3, _ := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": "adminB", "password": "AdminBpass1",
	}); c3 != http.StatusOK {
		t.Errorf("adminB 原口令失效（口令被越权改写）: %d", c3)
	}

	// —— 2b) 同类横向入口：停用 / 删除同级管理员同样应被拒 ——
	if c, _ := doJSON(t, r, http.MethodPost, "/api/users/status?id="+strconv.FormatInt(idB, 10), tokA,
		map[string]any{"status": "disabled"}); c != http.StatusForbidden {
		t.Errorf("adminA 停用同级 adminB 未被拒绝：HTTP %d", c)
	}
	if c, _ := doJSON(t, r, http.MethodPost, "/api/users/delete?id="+strconv.FormatInt(idB, 10), tokA, nil); c != http.StatusForbidden {
		t.Errorf("adminA 删除同级 adminB 未被拒绝：HTTP %d", c)
	}

	// —— 3) 反向断言：admin 仍可管理普通用户 ——
	if c, resp := doJSON(t, r, http.MethodPost, "/api/users/update?id="+strconv.FormatInt(idBob, 10), tokA,
		map[string]any{"password": "BobNewpass1"}); c != http.StatusOK {
		t.Errorf("admin 管理普通用户被误拒（过度收紧）: HTTP %d %v", c, resp["error"])
	}
}
