package handlers

import (
	"net/http"
	"testing"
)

// R11-03 回归测试：批量导入用户必须拒绝系统保留用户名。
//
// 背景：项目约定 isReservedUsername 必须覆盖**全部**建号/改名路径。R11 之前实际只覆盖
// handleCreateUser / handleUpdateUser / handleUpdateMe 三处，handleImportUsers 是第 4 条
// 建号路径且被遗漏——超管导入含 `root` 行的 CSV 会照单建号，出现与超管同名的普通账号，
// 破坏"用户名≠角色"的纵深防御约定。
//
// 断言：
//  1. 导入含 root/admin/system/superadmin 四行的 CSV → count==0、skipped==4；
//  2. 用户列表中不出现这些名字；
//  3. 反向断言：同批 CSV 中的普通用户名仍能正常导入（不过度收紧）。
func TestR11ImportRejectsReservedUsernames(t *testing.T) {
	r, _ := newTestServer(t)

	if c, _ := doJSON(t, r, http.MethodPost, "/api/setup", "", map[string]any{
		"username": "sa", "password": "SuperAdmin123",
	}); c != http.StatusOK {
		t.Fatalf("setup 超管失败: %d", c)
	}
	saTok := mustLogin(t, r, "sa", "SuperAdmin123")

	// 超管导入：四行均为系统保留名（大小写/空白混入，验证大小写不敏感 + TrimSpace）。
	csv := "username,password,email,role\n" +
		"root,RootPasswd1,root@mail.example,user\n" +
		" Admin ,AdminPasswd1,adminx@mail.example,user\n" +
		"SYSTEM,SystemPasswd1,system@mail.example,user\n" +
		"superadmin,SuperAdminPw1,superadminx@mail.example,user\n"

	code, resp := doJSON(t, r, http.MethodPost, "/api/users/import", saTok, map[string]any{"csv": csv})
	if code != http.StatusOK {
		t.Fatalf("导入请求失败: %d %v", code, resp["error"])
	}
	if count, _ := resp["count"].(float64); int(count) != 0 {
		t.Errorf("保留用户名不应被导入，count=%v（期望 0）", resp["count"])
	}
	if skipped, _ := resp["skipped"].(float64); int(skipped) != 4 {
		t.Errorf("四行保留名应全部计入 skipped，skipped=%v（期望 4）", resp["skipped"])
	}

	// 用户列表中不得出现这些保留名。
	_, ul := doJSON(t, r, http.MethodGet, "/api/users", saTok, nil)
	for _, u := range ul["users"].([]any) {
		name := u.(map[string]any)["username"].(string)
		if isReservedUsername(name) {
			t.Errorf("用户列表出现系统保留名 %q（R11-03 回归）", name)
		}
	}
	// 逐个确认无法用这些名字登录（即确实没被建号）。
	for _, n := range []string{"root", "Admin", "SYSTEM", "superadmin"} {
		if tok := r9TryLogin(t, r, n, "RootPasswd1"); tok != "" {
			t.Errorf("保留名 %q 被导入且可登录（R11-03 回归）", n)
		}
	}

	// 反向断言：普通用户名仍可正常导入。
	csvOK := "username,password,email,role\n" +
		"alice,AlicePasswd1,alice@mail.example,user\n" +
		"bob,BobPasswd11,bob@mail.example,user\n"
	code, resp = doJSON(t, r, http.MethodPost, "/api/users/import", saTok, map[string]any{"csv": csvOK})
	if code != http.StatusOK {
		t.Fatalf("正常导入请求失败: %d %v", code, resp["error"])
	}
	if count, _ := resp["count"].(float64); int(count) != 2 {
		t.Errorf("普通用户应正常导入，count=%v（期望 2）", resp["count"])
	}
	if tok := r9TryLogin(t, r, "alice", "AlicePasswd1"); tok == "" {
		t.Error("普通用户 alice 导入后无法登录（过度收紧）")
	}
}
