// Package db 负责 SQLite 连接、迁移、播种与元数据访问。
package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/uuid"
)

// Entry 密码条目（解密后的领域模型）。
//
// UUID 为全局唯一同步标识（PT-04）：客户端新条目自带随机 v4；存量条目由服务端
// 按 (user_id, id) 派生 v5 回填。为空表示该端仍是旧版协议，服务端会按旧逻辑
// （复合主键 (user_id, id)）处理并分配确定性 uuid。
type Entry struct {
	ID        int64  `json:"id"`
	UUID      string `json:"uuid"`
	SortOrder int64  `json:"sort_order"`
	Title     string `json:"title"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	URL       string `json:"url"`
	Category  string `json:"category"`
	Notes     string `json:"notes"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Deleted   bool   `json:"deleted"`
	// Pinned 置顶状态。
	// 入库（PUT /api/vault）时为指针，用于区分两种意图：
	//   - 携带具体值：网页端编辑、或已开启「置顶参与同步」的桌面端 → 采纳该值；
	//   - 未携带（nil）：已关闭「置顶参与同步」的桌面端 → 保留服务端已存状态，
	//     使桌面端按设备的置顶不被上传覆盖。
	// 出库（GET /api/vault）时始终为具体布尔值，便于各端直接使用。
	Pinned *bool `json:"pinned,omitempty"`
}

// User 用户信息。
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Avatar    string `json:"avatar"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// LogEntry 操作日志条目。
type LogEntry struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
	CreatedAt string `json:"created_at"`
}

// SiteConfig 站点信息（仅页脚文字）。
type SiteConfig struct {
	FooterText string `json:"footer_text"`
}

// sqliteDSN 为 DSN 追加并发安全 pragmas（若未配置）：
// busy_timeout 让并发写锁冲突时等待重试，而不是立即返回
// "database is locked"（在 HTTP 层表现为偶发 500）。
func sqliteDSN(dsn string) string {
	if strings.Contains(dsn, "_pragma") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=busy_timeout(5000)"
}

// Open 打开 SQLite 数据库并执行迁移与播种。
func Open(cfg config.Config) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqliteDSN(cfg.DBDSN))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := MigrateAt(db, cfg.DBDSN); err != nil {
		return nil, err
	}
	if err := SeedAdmin(db); err != nil {
		return nil, err
	}
	// PT-14：数据库文件（含 WAL/SHM）收紧为本用户可读写，避免同机其他账户读取
	// 密码库密文、账号哈希与配置。Windows 无 POSIX 权限语义，由安装目录 ACL 保护。
	hardenDataFilePerm(cfg.DBDSN)
	return db, nil
}

// hardenDataFilePerm 在类 Unix 系统上把数据文件权限收紧为 0600。
// 已是 0600 时不做任何操作；无法收紧时仅告警，不阻断启动。
func hardenDataFilePerm(dsn string) {
	if runtime.GOOS == "windows" || dsn == "" || strings.HasPrefix(dsn, ":memory:") {
		return
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dsn + suffix
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0o077 == 0 {
			continue
		}
		if err := os.Chmod(path, 0o600); err != nil {
			log.Printf("[db] 警告：无法收紧数据文件权限 %s: %v", path, err)
			continue
		}
		log.Printf("[db] 已将数据文件权限收紧为 0600: %s", path)
	}
}

// Migrate 建表并兼容旧库补列（不提供数据库文件路径，结构升级时跳过备份）。
// 生产入口应使用 MigrateAt 以便在破坏性结构升级前自动备份。
func Migrate(database *sql.DB) error {
	return MigrateAt(database, "")
}

// MigrateAt 在 Migrate 的基础上，于结构性升级（如主键变更）前自动备份数据库文件。
// dbPath 为 SQLite 文件路径（可为空或 :memory:，此时跳过备份）。
func MigrateAt(database *sql.DB, dbPath string) error {
	if err := migrateSchema(database); err != nil {
		return err
	}
	if err := migrateEntriesCompositePK(database, dbPath); err != nil {
		return err
	}
	// 复合主键重建会连带删除索引，因此 uuid 索引与回填放在最后执行。
	return migrateEntryUUIDs(database)
}

// migrateEntryUUIDs 确保 entries.uuid 唯一索引存在，并为存量空 uuid 回填确定性标识（PT-04）。
//
// 唯一索引为**部分索引**（WHERE uuid <> ''）：空值表示"旧版协议写入、待分配"，
// 不参与唯一性约束。
func migrateEntryUUIDs(db *sql.DB) error {
	const idxSQL = `CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_user_uuid ON entries(user_id, uuid) WHERE uuid <> ''`
	if _, err := db.Exec(idxSQL); err != nil {
		// 理论上不该出现重复 (user_id, uuid)。为不阻断启动：每组仅保留最早一行，
		// 其余置空（随后会被回填为新的确定性标识），再重建索引。
		if _, e2 := db.Exec(`UPDATE entries SET uuid = '' WHERE uuid <> '' AND rowid NOT IN (
			SELECT MIN(rowid) FROM entries WHERE uuid <> '' GROUP BY user_id, uuid)`); e2 != nil {
			return err
		}
		if _, e3 := db.Exec(idxSQL); e3 != nil {
			return e3
		}
	}
	return backfillEntryUUIDs(db)
}

// backfillEntryUUIDs 为 uuid 为空的存量条目回填 UUIDv5(user_id, id)。
//
// 幂等：已有非空 uuid 的行不受影响；重复执行得到相同的确定性值。
func backfillEntryUUIDs(db *sql.DB) error {
	rows, err := db.Query(`SELECT user_id, id FROM entries WHERE uuid = ''`)
	if err != nil {
		return err
	}
	type pair struct {
		userID int64
		id     int64
	}
	var items []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.userID, &p.id); err != nil {
			rows.Close()
			return err
		}
		items = append(items, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`UPDATE entries SET uuid = ? WHERE user_id = ? AND id = ?`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, it := range items {
		if _, err := stmt.Exec(uuid.Deterministic(it.userID, it.id), it.userID, it.id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// migrateSchema 建表并兼容旧库补列。
func migrateSchema(db *sql.DB) error {
	idClause := "INTEGER PRIMARY KEY AUTOINCREMENT"

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id ` + idClause + `,
			username VARCHAR(128) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(16) NOT NULL DEFAULT 'user',
			status VARCHAR(16) NOT NULL DEFAULT 'active',
			email VARCHAR(255) NOT NULL DEFAULT '',
			vault_key_enc TEXT NOT NULL DEFAULT '',
			kdf_salt TEXT NOT NULL DEFAULT '',
			token_version INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		// entries 主键为 (user_id, id) 复合键：id 由客户端本地自增提供，
		// 只有按用户隔离才能在多用户环境下避免"不同用户抢同一个 id"导致的写入失败。
		`CREATE TABLE IF NOT EXISTS entries (
			id INTEGER NOT NULL,
			uuid VARCHAR(64) NOT NULL DEFAULT '',
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
			deleted INTEGER NOT NULL DEFAULT 0,
			pinned INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS meta (
			key VARCHAR(128) PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS logs (
			id ` + idClause + `,
			user_id INTEGER NOT NULL DEFAULT 0,
			username VARCHAR(128) NOT NULL DEFAULT '',
			action VARCHAR(64) NOT NULL,
			detail VARCHAR(512) NOT NULL DEFAULT '',
			ip VARCHAR(64) NOT NULL DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS email_verifications (
			id ` + idClause + `,
			email VARCHAR(255) NOT NULL,
			code VARCHAR(64) NOT NULL,
			purpose VARCHAR(32) NOT NULL DEFAULT 'register',
			attempts INTEGER NOT NULL DEFAULT 0,
			expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	// 兼容旧库：为已存在的 users 表补充 email 列。
	if err := ensureColumn(db, "users", "email", "VARCHAR(255) NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 users 表补充 vault_key_enc 列（端到端加密 vault key 的密文）。
	if err := ensureColumn(db, "users", "vault_key_enc", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 users 表补充 kdf_salt 列（主密钥派生盐，替代以用户名作盐）。
	// 旧账号该列为空，客户端/前端回退用用户名作盐，保证既有数据仍可解密。
	if err := ensureColumn(db, "users", "kdf_salt", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 users 表补充 token_version 列（令牌版本，PT-06）。
	if err := ensureColumn(db, "users", "token_version", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 email_verifications 表补充 attempts 列（验证码尝试次数计数）。
	if err := ensureColumn(db, "email_verifications", "attempts", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 entries 表补充 deleted 墓碑列。
	if err := ensureColumn(db, "entries", "deleted", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 entries 表补充 pinned 置顶列（v0.2.34：置顶可选参与同步）。
	if err := ensureColumn(db, "entries", "pinned", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 users 表补充 pin_sync 列（按账号的「置顶参与同步」开关）。
	if err := ensureColumn(db, "users", "pin_sync", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 一次性迁移：0.2.33 曾把网页端置顶单独存在 vault_pins 表，v0.2.34 起并入
	// entries.pinned（按 user_id+uuid 对应），迁移完成后弃用该表。
	if ok, err := tableExists(db, "vault_pins"); err != nil {
		return err
	} else if ok {
		if _, err := db.Exec(`UPDATE entries SET pinned = 1 WHERE (user_id, uuid) IN (SELECT user_id, uuid FROM vault_pins)`); err != nil {
			return err
		}
		if _, err := db.Exec(`DROP TABLE IF EXISTS vault_pins`); err != nil {
			return err
		}
	}
	// 兼容旧库：为已存在的 entries 表补充 sort_order 序号列（若缺失），并按 id 顺序初始化旧数据。
	if err := ensureSortOrder(db); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 entries 表补充 uuid 同步标识列（PT-04）。
	if err := ensureColumn(db, "entries", "uuid", "VARCHAR(64) NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

// ensureSortOrder 为 entries 表补充 sort_order 序号列（若缺失），并按 id 顺序初始化旧数据。
func ensureSortOrder(db *sql.DB) error {
	exists, err := columnExists(db, "entries", "sort_order")
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := ensureColumn(db, "entries", "sort_order", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id, user_id FROM entries WHERE deleted = 0 ORDER BY user_id, id`)
	if err != nil {
		return err
	}
	type item struct {
		id     int64
		userID int64
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.userID); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	order := make(map[int64]int64)
	for _, it := range items {
		order[it.userID]++
		if _, err := db.Exec(`UPDATE entries SET sort_order = ? WHERE user_id = ? AND id = ?`, order[it.userID], it.userID, it.id); err != nil {
			return err
		}
	}
	return nil
}

// migrateEntriesCompositePK 确保 entries 表主键为 (user_id, id)。
//
// 背景：id 由客户端本地自增提供，若主键仅为全局唯一的 id，则第二个同步的
// 用户必然与已有记录冲突（插入失败 → 上传整个事务回滚 → 该用户永远无法同步）。
// SQLite 不支持修改主键，因此需要"表重建式迁移"：建新表 → 拷贝数据 → 换名。
//
// 安全性：升级前用 VACUUM INTO 生成一致性备份（备份失败则中止，不执行破坏性操作）；
// 迁移整体在同一事务内完成，可重复执行（幂等）。
func migrateEntriesCompositePK(db *sql.DB, dbPath string) error {
	// 表不存在（理论上不会，前面刚建过）→ 无需处理。
	var tableCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='entries'`).Scan(&tableCount); err != nil {
		return err
	}
	if tableCount == 0 {
		return nil
	}

	pk, err := entriesPKColumns(db)
	if err != nil {
		return err
	}
	if len(pk) == 2 && pk[0] == "user_id" && pk[1] == "id" {
		return nil // 已是目标结构
	}

	// 备份：仅在可确定文件路径时执行；失败即中止迁移。
	if path := sqliteFilePath(dbPath); path != "" {
		if err := backupDatabase(db, path); err != nil {
			return err
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE entries_pk_new (
			id INTEGER NOT NULL,
			uuid VARCHAR(64) NOT NULL DEFAULT '',
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
			deleted INTEGER NOT NULL DEFAULT 0,
			pinned INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, id)
		)`,
		// OR IGNORE：兜住历史脏数据中可能存在的 (user_id,id) 重复行，
		// 避免升级过程因个别脏数据整体失败。
		`INSERT OR IGNORE INTO entries_pk_new
			(id, uuid, sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned)
		 SELECT id, uuid, sort_order, user_id, title, username, url, category, password_enc, notes_enc, created_at, updated_at, deleted, pinned FROM entries`,
		`DROP TABLE entries`,
		`ALTER TABLE entries_pk_new RENAME TO entries`,
		`CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id)`,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// entriesPKColumns 返回 entries 表主键包含的列名（按主键顺序）。
func entriesPKColumns(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`PRAGMA table_info(entries)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type pkCol struct {
		seq  int
		name string
	}
	var cols []pkCol
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pkSeq     int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pkSeq); err != nil {
			return nil, err
		}
		if pkSeq > 0 {
			cols = append(cols, pkCol{seq: pkSeq, name: name})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// PRAGMA table_info 按列声明顺序返回，主键列需按 pk 序号（1,2,...）排序才是真实主键顺序。
	sort.Slice(cols, func(i, j int) bool { return cols[i].seq < cols[j].seq })
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, c.name)
	}
	return out, nil
}

// sqliteFilePath 从 DSN 中提取 SQLite 文件路径；内存库或无法确定时返回空串。
func sqliteFilePath(dsn string) string {
	s := strings.TrimSpace(dsn)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "file:")
	if s == "" || s == ":memory:" || strings.Contains(s, "mode=memory") {
		return ""
	}
	return s
}

// backupDatabase 用 VACUUM INTO 生成一致性备份（不阻塞读、结果自洽），
// 并只保留最近一份备份文件，避免长期占用磁盘。
func backupDatabase(db *sql.DB, path string) error {
	stamp := time.Now().Format("20060102-150405")
	target := path + ".bak-" + stamp
	if _, err := os.Stat(target); err == nil {
		_ = os.Remove(target) // 同名残留（同秒重复迁移）先清理
	}
	if _, err := db.Exec(`VACUUM INTO ?`, target); err != nil {
		return fmt.Errorf("升级前备份数据库失败（已中止迁移）：%w", err)
	}
	// 防御性校验：确认备份确实落盘，避免"以为备份了其实没有"。
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("升级前备份未生成（已中止迁移）：%w", err)
	}
	pruneOldBackups(path, target)
	return nil
}

// pruneOldBackups 删除除 keep 之外的旧备份文件。
// 注意：Windows 下 filepath.Glob 返回的路径分隔符可能与传入的 keep 不一致
// （如 keep 用正斜杠、Glob 结果用反斜杠），因此按文件名比较而非整串比较，
// 否则会把刚生成的备份误删。
func pruneOldBackups(dbPath, keep string) {
	matches, err := filepath.Glob(dbPath + ".bak-*")
	if err != nil {
		return
	}
	keepBase := filepath.Base(keep)
	for _, m := range matches {
		if filepath.Base(m) == keepBase {
			continue
		}
		_ = os.Remove(m)
	}
}

// ensureColumn 在列不存在时为表新增列（SQLite）。
func ensureColumn(db *sql.DB, table, column, def string) error {
	exists, err := columnExists(db, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + def)
	return err
}

// columnExists 检查表中是否存在指定列。
func columnExists(db *sql.DB, table, column string) (bool, error) {	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// tableExists 检查表是否存在（用于一次性数据迁移的守卫）。
func tableExists(db *sql.DB, table string) (bool, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name = ?`, table).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// FindNextUserID 返回当前最小可用的用户 ID，用于删除用户后回收复用 ID。
func FindNextUserID(db *sql.DB) (int64, error) {
	rows, err := db.Query(`SELECT id FROM users ORDER BY id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var expected int64 = 1
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		if id > expected {
			return expected, nil
		}
		expected = id + 1
	}
	return expected, rows.Err()
}

// SeedAdmin 不再创建默认账号；仅兼容旧库：将历史 admin 账号的 role 升级为 superadmin。
func SeedAdmin(db *sql.DB) error {
	_, err := db.Exec(`UPDATE users SET role = 'superadmin' WHERE username = 'admin' AND role = 'admin'`)
	return err
}

// TokenVersion 返回用户的当前令牌版本（不存在时返回 0）。
func TokenVersion(database *sql.DB, userID int64) int64 {
	var v int64
	if err := database.QueryRow(`SELECT COALESCE(token_version, 0) FROM users WHERE id = ?`, userID).Scan(&v); err != nil {
		return 0
	}
	return v
}

// BumpTokenVersion 递增用户的令牌版本，使其此前签发的全部 JWT 立即失效（PT-06）。
//
// JWT 是无状态的、无法直接吊销；版本号补上了这一点。用于「改密码后旧令牌立即作废」。
func BumpTokenVersion(database *sql.DB, userID int64) error {
	_, err := database.Exec(`UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id = ?`, userID)
	return err
}

// IsInitialized 返回是否已有用户（即是否已完成初始管理员设置）。
func IsInitialized(db *sql.DB) bool {
	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

// SetupAdmin 首次创建超级管理员（passwordHash 为已哈希的密码），返回新用户 ID。
func SetupAdmin(db *sql.DB, username, passwordHash, email, kdfSalt string) (int64, error) {
	res, err := db.Exec(`INSERT INTO users (username, password_hash, role, status, email, kdf_salt) VALUES (?, ?, 'superadmin', 'active', ?, ?)`, username, passwordHash, email, kdfSalt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// setupMu 串行化「检查是否已初始化 + 创建管理员」这一临界区，避免并发重复初始化。
var setupMu sync.Mutex

// SetupAdminIfEmpty 仅在系统尚无任何用户时创建超级管理员。
// created 为 false 表示系统已初始化、未执行写入。
func SetupAdminIfEmpty(db *sql.DB, username, passwordHash, email, kdfSalt string) (id int64, created bool, err error) {
	setupMu.Lock()
	defer setupMu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var count int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return 0, false, err
	}
	if count > 0 {
		return 0, false, nil
	}
	res, err := tx.Exec(`INSERT INTO users (username, password_hash, role, status, email, kdf_salt) VALUES (?, ?, 'superadmin', 'active', ?, ?)`,
		username, passwordHash, email, kdfSalt)
	if err != nil {
		return 0, false, err
	}
	newID, err := res.LastInsertId()
	if err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return newID, true, nil
}

// SetMeta 写入或更新一条元数据。
func SetMeta(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`, key, value)
	return err
}

// GetMeta 读取一条元数据，不存在返回空字符串。
// DeleteMeta 删除一个 meta 键（不存在时视为成功）。
// 用于把密钥类配置从数据库迁移到独立文件后清理旧值（PT-07）。
func DeleteMeta(db *sql.DB, key string) error {
	_, err := db.Exec(`DELETE FROM meta WHERE key = ?`, key)
	return err
}

func GetMeta(db *sql.DB, key string) string {
	var v string
	_ = db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v
}

// LoadSiteConfig 从 meta 读取站点信息（页脚文字）。
func LoadSiteConfig(db *sql.DB) SiteConfig {
	return SiteConfig{
		FooterText: GetMeta(db, "site_footer_text"),
	}
}
