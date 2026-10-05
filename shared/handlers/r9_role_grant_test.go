package handlers

import (
	"net/http"
	"strconv"
	"testing"
)

// R9-01 回归测试：仅超级管理员可创建/授予管理员角色。
//
// 背景：R8-01 收紧了 CanManageUser（admin 不能管理同级 admin），但 admin 仍可经
// handleCreateUser（role=admin）/ handleUpdateUser（把 user 升为 admin）/
// handleImportUsers（CSV 角色列）三条路径"造"出管理员，从而绕开同级隔离——
// 被造出的管理员不归自己管，却成了新的特权账号，构成提权旁路。
// 修复后这三条路径都要求操作者为 superadmin。
//
// 覆盖：
//  1) admin 创建 admin → 403，且纵深确认该账号不存在；
//  2) admin 把普通用户提升为 admin → 403，且角色未被改写；
//  3) admin 借批量导入创建 admin → 该行被跳过（账号不存在）；
//  4) 反向断言：admin 仍可创建普通用户；superadmin 仍可创建/授予 admin。
func TestR9AdminCannotGrantAdminRole(t *testing.T) {
	r, _ := newTestServer(t)

	if c, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	}); c != http.StatusOK {
		t.Fatalf("setup 超管失败: %d", c)
	}
	saTok := mustLogin(t, r, "sa", "SuperAdmin123")

	// 超管（特权方）创建 admin 与普通用户：均允许。
	if c, resp := doJSON(t, r, http.MethodPost, "/api/users", saTok, map[string]any{
		"username": "adminA", "password": "AdminApass1", "email": "adminA@mail.example", "role": "admin",
	}); c != http.StatusOK {
		t.Fatalf("超管创建 admin 失败: %d %v", c, resp["error"])
	}
	if c, resp := doJSON(t, r, http.MethodPost, "/api/users", saTok, map[string]any{
		"username": "bob", "password": "BobPasswd1", "email": "bob@mail.example", "role": "user",
	}); c != http.StatusOK {
		t.Fatalf("超管创建普通用户失败: %d %v", c, resp["error"])
	}
	tokA := mustLogin(t, r, "adminA", "AdminApass1")
	idBob := r9UserID(t, r, saTok, "bob")

	// —— 1) admin 创建 admin → 403 ——
	c, resp := doJSON(t, r, http.MethodPost, "/api/users", tokA, map[string]any{
		"username": "adminC", "password": "AdminCpass1", "email": "adminC@mail.example", "role": "admin",
	})
	if c != http.StatusForbidden {
		t.Errorf("admin 创建管理员未被拒绝：HTTP %d %v", c, resp["error"])
	}
	if tok := r9TryLogin(t, r, "adminC", "AdminCpass1"); tok != "" {
		t.Errorf("admin 越权创建出了可登录的管理员 adminC")
	}

	// —— 2) admin 把普通用户提升为 admin → 403 ——
	c, resp = doJSON(t, r, http.MethodPost, "/api/users/update?id="+strconv.FormatInt(idBob, 10), tokA, map[string]any{
		"role": "admin",
	})
	if c != http.StatusForbidden {
		t.Errorf("admin 授予管理员角色未被拒绝：HTTP %d %v", c, resp["error"])
	}
	if role := r9RoleOf(t, r, saTok, idBob); role != "user" {
		t.Errorf("bob 的角色被越权提升为 %q", role)
	}

	// —— 3) admin 借批量导入创建 admin → 该行被跳过 ——
	csv := "username,password,email,role\nimpadmin,ImpAdminP1,impadmin@mail.example,admin\n"
	if c, resp = doJSON(t, r, http.MethodPost, "/api/users/import", tokA, map[string]any{"csv": csv}); c != http.StatusOK {
		t.Fatalf("导入请求失败: %d %v", c, resp["error"])
	}
	if tok := r9TryLogin(t, r, "impadmin", "ImpAdminP1"); tok != "" {
		t.Errorf("admin 借批量导入越权创建出了可登录的管理员 impadmin")
	}

	// —— 4) 反向断言：admin 仍可创建普通用户（不过度收紧）——
	if c, resp = doJSON(t, r, http.MethodPost, "/api/users", tokA, map[string]any{
		"username": "carol", "password": "CarolPass1", "email": "carol@mail.example", "role": "user",
	}); c != http.StatusOK {
		t.Errorf("admin 创建普通用户被误拒: %d %v", c, resp["error"])
	}

	// —— 4b) 超管仍可把普通用户提升为 admin（正向）——
	if c, resp = doJSON(t, r, http.MethodPost, "/api/users/update?id="+strconv.FormatInt(idBob, 10), saTok, map[string]any{
		"role": "admin",
	}); c != http.StatusOK {
		t.Errorf("超管授予管理员角色被误拒: %d %v", c, resp["error"])
	}
	if role := r9RoleOf(t, r, saTok, idBob); role != "admin" {
		t.Errorf("超管授予管理员角色未生效，role=%q", role)
	}
}

// r9TryLogin 尝试登录，成功返回 token，失败返回空串（不终止测试）。
func r9TryLogin(t *testing.T, r http.Handler, username, password string) string {
	t.Helper()
	code, resp := doJSON(t, r, http.MethodPost, "/api/login", "", map[string]any{
		"username": username, "password": password,
	})
	if code != http.StatusOK {
		return ""
	}
	tok, _ := resp["token"].(string)
	return tok
}

// r9UserID 按用户名查 id（需要管理员 token）。
func r9UserID(t *testing.T, r http.Handler, tok, name string) int64 {
	t.Helper()
	_, resp := doJSON(t, r, http.MethodGet, "/api/users", tok, nil)
	for _, u := range resp["users"].([]any) {
		m := u.(map[string]any)
		if m["username"] == name {
			return int64(m["id"].(float64))
		}
	}
	t.Fatalf("未找到用户 %s", name)
	return 0
}

// r9RoleOf 查询指定 id 的角色。
func r9RoleOf(t *testing.T, r http.Handler, tok string, id int64) string {
	t.Helper()
	_, resp := doJSON(t, r, http.MethodGet, "/api/users", tok, nil)
	for _, u := range resp["users"].([]any) {
		m := u.(map[string]any)
		if int64(m["id"].(float64)) == id {
			return m["role"].(string)
		}
	}
	t.Fatalf("未找到 id=%d 的用户", id)
	return ""
}
