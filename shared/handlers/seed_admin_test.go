package handlers

import (
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestSeedAdminDoesNotReEscalateOnEveryStartup 锁定 S-01：启动期不得把
// username="admin" 的普通管理员无条件提升为 superadmin。
//
// 回归背景：早期 SeedAdmin 每次 Open 都执行
// `UPDATE users SET role='superadmin' WHERE username='admin' AND role='admin'`。
// 由于 handleCreateUser / handleUpdateUser 允许管理员创建或改名出
// username="admin"、role="admin" 的账号，任一普通管理员都能借此在下次重启后被静默
// 提权。修复后改为一次性、带版本守卫、且仅当全库无 superadmin 时才执行的迁移。
func TestSeedAdminDoesNotReEscalateOnEveryStartup(t *testing.T) {
	_, database := newTestServer(t)

	// 构造「已有 superadmin」的正常库：再加一个名为 admin 的普通管理员。
	if err := db.SetMeta(database, "seed_admin_migrated", "1"); err != nil {
		t.Fatalf("set meta: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (id, username, password_hash, role, status, email) VALUES (900, 'root', '$2a$12$x', 'superadmin', 'active', 'root@example.com')`); err != nil {
		t.Fatalf("insert superadmin: %v", err)
	}
	// 普通管理员试图借 "admin" 用户名提权。
	if _, err := database.Exec(`INSERT INTO users (id, username, password_hash, role, status, email) VALUES (901, 'admin', '$2a$12$x', 'admin', 'active', 'admin@example.com')`); err != nil {
		t.Fatalf("insert admin: %v", err)
	}

	// 模拟重启时再次执行播种迁移。
	if err := db.SeedAdmin(database); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	var role string
	if err := database.QueryRow(`SELECT role FROM users WHERE id = 901`).Scan(&role); err != nil {
		t.Fatalf("query: %v", err)
	}
	if role != "admin" {
		t.Fatalf("username=admin 的普通管理员被静默提权为 %q（应为 admin）", role)
	}
}

// TestSeedAdminUpgradesLegacyDatabaseOnceLegitimately 反向确认：真正的旧库（全库无
// superadmin，仅有一个名为 admin 的普通管理员）仍应被正常升级，避免修复过度。
func TestSeedAdminUpgradesLegacyDatabaseOnceLegitimately(t *testing.T) {
	_, database := newTestServer(t)

	// 清掉测试夹具可能写入的标记，模拟从未迁移过的旧库。
	if _, err := database.Exec(`DELETE FROM meta WHERE key = 'seed_admin_migrated'`); err != nil {
		t.Fatalf("clear meta: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM users`); err != nil {
		t.Fatalf("clear users: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (id, username, password_hash, role, status, email) VALUES (1, 'admin', '$2a$12$x', 'admin', 'active', 'admin@example.com')`); err != nil {
		t.Fatalf("insert admin: %v", err)
	}

	if err := db.SeedAdmin(database); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	var role string
	if err := database.QueryRow(`SELECT role FROM users WHERE id = 1`).Scan(&role); err != nil {
		t.Fatalf("query: %v", err)
	}
	if role != "superadmin" {
		t.Fatalf("旧库 admin 应被升级为 superadmin，实际为 %q", role)
	}

	// 迁移标记应已写入，且再次调用不改变结果（幂等、只跑一次）。
	if got := db.GetMeta(database, "seed_admin_migrated"); got != "1" {
		t.Fatalf("迁移标记未写入，实际 %q", got)
	}
	if err := db.SeedAdmin(database); err != nil {
		t.Fatalf("二次 seed: %v", err)
	}
}
