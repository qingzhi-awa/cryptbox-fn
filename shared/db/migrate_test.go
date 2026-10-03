package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/qingzhi-awa/cryptbox/shared/uuid"
)

// legacyEntriesSchema 旧结构：entries.id 为全表唯一主键（修复前的形态）。
const legacyEntriesSchema = `CREATE TABLE entries (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	sort_order INTEGER NOT NULL DEFAULT 0,
	user_id INTEGER NOT NULL,
	title VARCHAR(255) NOT NULL,
	username VARCHAR(255) NOT NULL DEFAULT '',
	url VARCHAR(512) NOT NULL DEFAULT '',
	category VARCHAR(128) NOT NULL DEFAULT '',
	password_enc TEXT NOT NULL,
	notes_enc TEXT NOT NULL,
	created_at VARCHAR(64) NOT NULL,
	updated_at VARCHAR(64) NOT NULL,
	deleted INTEGER NOT NULL DEFAULT 0
)`

func insertEntry(t *testing.T, database *sql.DB, id, userID int64, title string) {
	t.Helper()
	if _, err := database.Exec(
		`INSERT INTO entries (id, sort_order, user_id, title, password_enc, notes_enc, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		id, id, userID, title, "enc", "enc", "2026-10-03T00:00:00Z", "2026-10-03T00:00:00Z"); err != nil {
		t.Fatalf("insert entry: %v", err)
	}
}

// TestMigrateEntriesCompositePK 验证旧库升级到 (user_id,id) 复合主键：
// 数据完整、主键生效（不同用户可用相同 id）、自动备份、可重复执行（幂等）。
func TestMigrateEntriesCompositePK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer database.Close()

	if _, err := database.Exec(legacyEntriesSchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	// 旧结构下 id 全表唯一：userA 占 1,2；userB 占 3。
	insertEntry(t, database, 1, 100, "A-1")
	insertEntry(t, database, 2, 100, "A-2")
	insertEntry(t, database, 3, 200, "B-3")

	// 执行升级：应自动备份旧库。
	if err := MigrateAt(database, path); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	backups, _ := filepath.Glob(path + ".bak-*")
	if len(backups) != 1 {
		t.Fatalf("期望生成 1 份升级前备份，实际 %d 份", len(backups))
	}

	// 主键应为 (user_id,id)。
	pk, err := entriesPKColumns(database)
	if err != nil {
		t.Fatalf("read pk: %v", err)
	}
	if len(pk) != 2 || pk[0] != "user_id" || pk[1] != "id" {
		t.Fatalf("主键应为 (user_id,id)，实际 %v", pk)
	}

	// 数据完整。
	var count int
	if err := database.QueryRow(`SELECT COUNT(1) FROM entries`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("迁移后条目数应为 3，实际 %d (err=%v)", count, err)
	}
	var title string
	if err := database.QueryRow(`SELECT title FROM entries WHERE user_id=200 AND id=3`).Scan(&title); err != nil || title != "B-3" {
		t.Fatalf("迁移后数据应保持原样，实际 title=%q err=%v", title, err)
	}

	// 关键回归：不同用户可以使用相同 id。
	insertEntry(t, database, 1, 200, "B-1")
	insertEntry(t, database, 1, 300, "C-1")

	// 幂等：重复执行不报错、不产生新备份。
	if err := MigrateAt(database, path); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	backups, _ = filepath.Glob(path + ".bak-*")
	if len(backups) != 1 {
		t.Fatalf("幂等执行不应新增备份，实际 %d 份", len(backups))
	}
	var total int
	if err := database.QueryRow(`SELECT COUNT(1) FROM entries`).Scan(&total); err != nil || total != 5 {
		t.Fatalf("重复迁移后条目数应为 5，实际 %d (err=%v)", total, err)
	}

	// 同一用户内重复 id 仍应被主键拒绝（保证按用户唯一）。
	if _, err := database.Exec(
		`INSERT INTO entries (id, sort_order, user_id, title, password_enc, notes_enc, created_at, updated_at)
		 VALUES (1,1,300,'dup','e','e','x','x')`); err == nil {
		t.Fatal("同一用户下重复 id 应触发主键冲突")
	}
}

// TestMigrateEntriesCompositePK_FreshDatabase 新库直接建为复合主键，且不产生备份。
func TestMigrateEntriesCompositePK_FreshDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer database.Close()

	if err := MigrateAt(database, path); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pk, err := entriesPKColumns(database)
	if err != nil {
		t.Fatalf("read pk: %v", err)
	}
	if len(pk) != 2 || pk[0] != "user_id" || pk[1] != "id" {
		t.Fatalf("新库主键应为 (user_id,id)，实际 %v", pk)
	}
	if backups, _ := filepath.Glob(path + ".bak-*"); len(backups) != 0 {
		t.Fatalf("新库无需备份，实际 %d 份", len(backups))
	}
}

// TestMigrateBackupKeptWithForwardSlashPath 回归实际部署中踩到的问题：
// DSN 使用正斜杠路径（如 H:/data/app.db）时，filepath.Glob 在 Windows 上返回的
// 分隔符不同，早期实现会把刚生成的备份误判为"旧备份"删除 → 等于没有备份。
func TestMigrateBackupKeptWithForwardSlashPath(t *testing.T) {
	dir := t.TempDir()
	// 故意用正斜杠拼接路径，模拟真实 DSN 写法。
	fwd := filepath.ToSlash(filepath.Join(dir, "slash.db"))
	database, err := sql.Open("sqlite", fwd)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer database.Close()
	if _, err := database.Exec(legacyEntriesSchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	insertEntry(t, database, 1, 100, "A-1")

	if err := MigrateAt(database, fwd); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	backups, _ := filepath.Glob(fwd + ".bak-*")
	if len(backups) != 1 {
		t.Fatalf("升级后应保留 1 份备份，实际 %d 份（备份被误删会导致无法回滚）", len(backups))
	}
	if _, err := os.Stat(backups[0]); err != nil {
		t.Fatalf("备份文件应真实存在: %v", err)
	}
}

// TestHardenDataFilePerm 验证 PT-14：类 Unix 上数据库文件权限被收紧为 0600，
// 已合规时不改动，Windows 上为无操作（权限由目录 ACL 决定）。
func TestHardenDataFilePerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		// 仍应可安全调用（无副作用、不 panic）。
		hardenDataFilePerm(filepath.Join(t.TempDir(), "nope.db"))
		hardenDataFilePerm("")
		hardenDataFilePerm(":memory:")
		t.Skip("Windows 无 POSIX 权限语义，由安装目录 ACL 保护")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	hardenDataFilePerm(path)
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("权限应被收紧为 0600，实际 %o", info.Mode().Perm())
	}
	// 幂等：再次调用不报错。
	hardenDataFilePerm(path)
}

// TestMigrateBackfillsEntryUUIDs 验证 PT-04：旧库升级后
//   - 存量条目 uuid 被回填为 UUIDv5(user_id, id)（确定性、各端一致）；
//   - 唯一索引 (user_id, uuid) 生效（不同用户可用相同 uuid，同用户重复则拒绝）；
//   - 重复执行迁移幂等（uuid 不再变化）。
func TestMigrateBackfillsEntryUUIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer database.Close()

	if _, err := database.Exec(legacyEntriesSchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	// 旧结构下 id 全表唯一，因此这里必须用互不相同的 id。
	insertEntry(t, database, 1, 100, "A-1")
	insertEntry(t, database, 2, 100, "A-2")
	insertEntry(t, database, 3, 200, "B-3")

	if err := MigrateAt(database, path); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	snapshot := func() map[string]string {
		rows, err := database.Query(`SELECT user_id, id, uuid FROM entries ORDER BY user_id, id`)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var uid, eid int64
			var u string
			if err := rows.Scan(&uid, &eid, &u); err != nil {
				t.Fatalf("scan: %v", err)
			}
			key := fmt.Sprintf("%d:%d", uid, eid)
			if u == "" {
				t.Fatalf("%s 的 uuid 未回填", key)
			}
			want := uuid.Deterministic(uid, eid)
			if u != want {
				t.Fatalf("%s uuid 应为 %q，实际 %q", key, want, u)
			}
			out[key] = u
		}
		if len(out) != 3 {
			t.Fatalf("应回填 3 条，实际 %d 条", len(out))
		}
		return out
	}
	first := snapshot()

	// 幂等：再次迁移不应改变任何 uuid。
	if err := MigrateAt(database, path); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	for k, v := range snapshot() {
		if first[k] != v {
			t.Fatalf("重复迁移改变了 %s 的 uuid：%q → %q", k, first[k], v)
		}
	}

	// 唯一索引：同用户重复 uuid 必须被拒。
	if _, err := database.Exec(
		`INSERT INTO entries (id, uuid, sort_order, user_id, title, password_enc, notes_enc, created_at, updated_at)
		 VALUES (9, ?, 9, 100, 'dup-uuid', 'e', 'e', 'x', 'x')`,
		first["100:1"]); err == nil {
		t.Fatal("同用户重复 uuid 应触发唯一索引冲突")
	}
	// 不同用户可用相同 uuid（按用户隔离）。
	if _, err := database.Exec(
		`INSERT INTO entries (id, uuid, sort_order, user_id, title, password_enc, notes_enc, created_at, updated_at)
		 VALUES (9, ?, 9, 300, 'other-user', 'e', 'e', 'x', 'x')`,
		first["100:1"]); err != nil {
		t.Fatalf("不同用户使用相同 uuid 应被允许: %v", err)
	}
}
