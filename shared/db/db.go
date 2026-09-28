// Package db 负责 SQLite 连接、迁移、播种与元数据访问。
package db

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"

	"github.com/qingzhi-awa/cryptbox/shared/config"
)

// Entry 密码条目（解密后的领域模型）。
type Entry struct {
	ID        int64  `json:"id"`
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

// Open 打开 SQLite 数据库并执行迁移与播种。
func Open(cfg config.Config) (*sql.DB, error) {
	db, err := sql.Open("sqlite", cfg.DBDSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := Migrate(db); err != nil {
		return nil, err
	}
	if err := SeedAdmin(db); err != nil {
		return nil, err
	}
	return db, nil
}

// Migrate 建表并兼容旧库补列。
func Migrate(db *sql.DB) error {
	idClause := "INTEGER PRIMARY KEY AUTOINCREMENT"

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id ` + idClause + `,
			username VARCHAR(128) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(16) NOT NULL DEFAULT 'user',
			status VARCHAR(16) NOT NULL DEFAULT 'active',
			email VARCHAR(255) NOT NULL DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS entries (
			id ` + idClause + `,
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
	// 兼容旧库：为已存在的 entries 表补充 deleted 墓碑列。
	if err := ensureColumn(db, "entries", "deleted", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 兼容旧库：为已存在的 entries 表补充 sort_order 序号列（若缺失），并按 id 顺序初始化旧数据。
	if err := ensureSortOrder(db); err != nil {
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
		if _, err := db.Exec(`UPDATE entries SET sort_order = ? WHERE id = ?`, order[it.userID], it.id); err != nil {
			return err
		}
	}
	return nil
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
func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
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

// IsInitialized 返回是否已有用户（即是否已完成初始管理员设置）。
func IsInitialized(db *sql.DB) bool {
	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

// SetupAdmin 首次创建超级管理员（passwordHash 为已哈希的密码），返回新用户 ID。
func SetupAdmin(db *sql.DB, username, passwordHash, email string) (int64, error) {
	res, err := db.Exec(`INSERT INTO users (username, password_hash, role, status, email) VALUES (?, ?, 'superadmin', 'active', ?)`, username, passwordHash, email)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetMeta 写入或更新一条元数据。
func SetMeta(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`, key, value)
	return err
}

// GetMeta 读取一条元数据，不存在返回空字符串。
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
