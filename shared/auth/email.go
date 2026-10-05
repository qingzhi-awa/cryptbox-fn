package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/qingzhi-awa/cryptbox/shared/crypto"
	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// smtpEncPrefix 标记"已加密存储"的 SMTP 口令（PT-07）。
const smtpEncPrefix = "enc:"

// MaskedSecret 是配置导出时用于替换敏感字段的掩码；导入时遇到该值表示"保持原值"。
const MaskedSecret = "******"

// EncryptSMTPPassword 用服务端静态密钥加密 SMTP 口令（存库时带 enc: 前缀）。
//
// 幂等：入参已带 enc: 前缀时原样返回。这防止「导入一份内部保留密文的配置」时把密文
// 二次加密，导致解密后得到字面量 "enc:..." 而 SMTP 静默失效（与 MigrateSMTPPassword
// 的幂等语义保持一致）。
func EncryptSMTPPassword(encKey []byte, plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if strings.HasPrefix(plain, smtpEncPrefix) {
		return plain, nil
	}
	if len(encKey) == 0 {
		return "", errors.New("服务端加密密钥未就绪，拒绝以明文保存 SMTP 口令")
	}
	ct, err := crypto.AESEncryptString(encKey, plain)
	if err != nil {
		return "", err
	}
	return smtpEncPrefix + ct, nil
}

// DecryptSMTPPassword 解密 SMTP 口令；兼容历史明文（无前缀时原样返回）。
func DecryptSMTPPassword(encKey []byte, stored string) string {
	if stored == "" {
		return ""
	}
	if !strings.HasPrefix(stored, smtpEncPrefix) {
		return stored // 历史明文，待 MigrateSMTPPassword 升级
	}
	if len(encKey) == 0 {
		return ""
	}
	plain, err := crypto.AESDecryptString(encKey, strings.TrimPrefix(stored, smtpEncPrefix))
	if err != nil {
		return ""
	}
	return plain
}

// MigrateSMTPPassword 把历史明文 SMTP 口令升级为密文存储（幂等）。
// 无密钥或已是密文时跳过。
func MigrateSMTPPassword(database *sql.DB, encKey []byte) error {
	stored := db.GetMeta(database, "smtp_password")
	if stored == "" || strings.HasPrefix(stored, smtpEncPrefix) || len(encKey) == 0 {
		return nil
	}
	enc, err := EncryptSMTPPassword(encKey, stored)
	if err != nil {
		return err
	}
	return db.SetMeta(database, "smtp_password", enc)
}

//go:embed logo.png
var logoPNG []byte

// LogoDataURI 返回 logo 图片的 base64 data URI（用于 HTML 邮件内嵌）。
func LogoDataURI() string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(logoPNG)
}

// SMTPConfig 邮件配置。
type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	SSL      bool   `json:"ssl"`
	Vendor   string `json:"vendor"`
}

// LoadSMTPConfig 从 meta 读取 SMTP 配置（口令按需用服务端静态密钥解密，PT-07）。
func LoadSMTPConfig(database *sql.DB, encKey []byte) SMTPConfig {
	port, _ := strconv.Atoi(db.GetMeta(database, "smtp_port"))
	vendor := db.GetMeta(database, "smtp_vendor")
	if vendor == "" {
		vendor = "qq"
	}
	return SMTPConfig{
		Host:     db.GetMeta(database, "smtp_host"),
		Port:     port,
		Username: db.GetMeta(database, "smtp_username"),
		Password: DecryptSMTPPassword(encKey, db.GetMeta(database, "smtp_password")),
		From:     db.GetMeta(database, "smtp_from"),
		SSL:      db.GetMeta(database, "smtp_ssl") == "true",
		Vendor:   vendor,
	}
}

// EmailVerifyMode 返回邮箱验证模式：code / link / none。
func EmailVerifyMode(database *sql.DB) string {
	m := db.GetMeta(database, "email_verify_mode")
	if m != "code" && m != "link" && m != "none" {
		return "none"
	}
	return m
}

// SMTPConfigured 返回是否已配置 SMTP。
// 只关心主机与端口，因此不读取（也无需解密）口令。
func SMTPConfigured(database *sql.DB) bool {
	port, _ := strconv.Atoi(db.GetMeta(database, "smtp_port"))
	return db.GetMeta(database, "smtp_host") != "" && port != 0
}

// SMTPEnabled 返回是否启用 SMTP（未显式设置时，默认根据是否已配置判断）。
func SMTPEnabled(database *sql.DB) bool {
	v := db.GetMeta(database, "smtp_enabled")
	if v == "true" {
		return true
	}
	if v == "false" {
		return false
	}
	return SMTPConfigured(database)
}

// AllowRegistration 返回是否允许注册：需显式开启且已启用并配置 SMTP（才能发送验证码）。
func AllowRegistration(database *sql.DB) bool {
	if db.GetMeta(database, "allow_registration") != "true" {
		return false
	}
	return SMTPEnabled(database) && SMTPConfigured(database)
}

// PasswordMinLength 返回密码最小长度（默认 6）。
// 未显式配置时以 6 为准；超级管理员账号另有更严的下限（见 SuperAdminMinLength）。
func PasswordMinLength(database *sql.DB) int {
	if v := db.GetMeta(database, "password_min_length"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 6
}

// SuperAdminMinLength 超级管理员口令的最小长度（不随 password_min_length 放宽而降低）。
const SuperAdminMinLength = 10

// PasswordRequireComplex 是否要求口令同时包含字母与数字。
// 默认开启；仅当管理员显式关闭（meta 值为 "false"）时才跳过复杂度校验。
func PasswordRequireComplex(database *sql.DB) bool {
	return db.GetMeta(database, "password_require_complex") != "false"
}

// ValidatePassword 校验新口令是否满足要求。
func ValidatePassword(database *sql.DB, password string) error {
	minLen := PasswordMinLength(database)
	if len(password) < minLen {
		return errors.New("密码至少 " + strconv.Itoa(minLen) + " 位")
	}
	return validateComplexity(database, password)
}

// ValidateSuperAdminPassword 校验超级管理员口令：长度不低于 SuperAdminMinLength，且必须满足复杂度要求。
func ValidateSuperAdminPassword(database *sql.DB, password string) error {
	if len(password) < SuperAdminMinLength {
		return errors.New("超级管理员密码至少 " + strconv.Itoa(SuperAdminMinLength) + " 位")
	}
	return validateComplexity(database, password)
}

func validateComplexity(database *sql.DB, password string) error {
	if !PasswordRequireComplex(database) {
		return nil
	}
	hasLetter, hasDigit := false, false
	for _, c := range password {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		} else if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return errors.New("密码需同时包含字母和数字")
	}
	return nil
}

// sendMail 发送邮件（通用，contentType 为 text/plain 或 text/html）。
func sendMail(database *sql.DB, encKey []byte, to, subject, contentType, body string) error {
	return sendMailWithConfig(LoadSMTPConfig(database, encKey), to, subject, contentType, body)
}

// smtpTimeout 建连与单次写读的截止时间：避免出站 SMTP 端口被防火墙静默丢弃时
// 连接无限挂起（安装向导会卡在 -test-smtp，用户表现为"发送不了邮件"）。
const smtpTimeout = 20 * time.Second

// sanitizeHeader 清洗会被写入邮件头的字段：去掉 CR/LF，防止头部注入，
// 同时避免收件人/主题里的换行破坏报文结构。
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}

// encodeHeaderValue 对含非 ASCII 的头部值做 RFC 2047 编码。
// 中文主题裸传会被部分 SMTP 服务器拒收（550）或客户端显示乱码。
func encodeHeaderValue(s string) string {
	ascii := true
	for _, r := range s {
		if r > 0x7f {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	return mime.BEncoding.Encode("UTF-8", s)
}

// encodeBodyBase64 把正文按 RFC 2045 base64 编码（每行 76 字符），
// 保证中文/HTML 正文在只支持 7bit 的服务器上也能无损投递。
func encodeBodyBase64(body string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	return b.String()
}

// buildMessage 组装 RFC 5322 报文：补齐 Date/Message-ID，编码主题与正文。
func buildMessage(from, to, subject, contentType, body string) []byte {
	from = sanitizeHeader(from)
	to = sanitizeHeader(to)
	subject = encodeHeaderValue(sanitizeHeader(subject))
	contentType = sanitizeHeader(contentType)
	if contentType == "" {
		contentType = "text/plain; charset=UTF-8"
	}
	mid := make([]byte, 16)
	_, _ = rand.Read(mid)
	domain := "cryptbox.local"
	if i := strings.LastIndex(from, "@"); i >= 0 && i+1 < len(from) {
		domain = from[i+1:]
	}
	hdrs := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: <" + hex.EncodeToString(mid) + "@" + domain + ">\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" + encodeBodyBase64(body)
	return []byte(hdrs)
}

// sendMailWithConfig 使用给定的 SMTP 配置发送邮件。
// 支持两种加密模式：隐式 TLS（SSL=true，通常 465）与 STARTTLS（SSL=false，通常 587）。
func sendMailWithConfig(cfg SMTPConfig, to, subject, contentType, body string) error {
	if cfg.Host == "" || cfg.Port == 0 {
		return errors.New("SMTP 未配置（缺少服务器地址或端口）")
	}
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}
	if from == "" {
		return errors.New("SMTP 发件人地址为空")
	}
	// 需要认证却拿不到口令：多为口令解密失败或未填写。显式报错，避免退化成
	// "认证失败"这类难以定位的模糊错误。
	if cfg.Username != "" && cfg.Password == "" {
		return errors.New("SMTP 口令为空或解密失败，请在系统设置中重新填写邮箱授权码")
	}

	msg := buildMessage(from, to, subject, contentType, body)
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: smtpTimeout}

	var conn net.Conn
	var err error
	if cfg.SSL {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName: cfg.Host,
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("连接 SMTP 服务器 %s 失败: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer c.Close()

	// 非隐式 TLS：服务器提供 STARTTLS 时强制升级（587 端口的标准做法），
	// 既保证凭据加密传输，也让 smtp.PlainAuth 能正常发送。
	if !cfg.SSL {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("STARTTLS 升级失败: %w", err)
			}
		}
	}

	if cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("SMTP 服务器不支持 AUTH 认证")
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("SMTP 认证失败（请确认授权码/发件人与账号一致）: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM 被拒绝: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO 被拒绝: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA 被拒绝: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// TestSMTP 使用显式 SMTP 参数发送一封测试邮件（供安装向导校验 SMTP 配置）。
func TestSMTP(host string, port int, username, password string, ssl bool, to string) error {
	cfg := SMTPConfig{Host: host, Port: port, Username: username, Password: password, SSL: ssl}
	return sendMailWithConfig(cfg, to, "密匣 CryPtBox 测试邮件", "text/html; charset=UTF-8", TestEmailHTML())
}

// SendEmail 发送纯文本邮件。
func SendEmail(database *sql.DB, encKey []byte, to, subject, body string) error {
	return sendMail(database, encKey, to, subject, "text/plain; charset=UTF-8", body)
}

// SendHTMLEmail 发送 HTML 邮件。
func SendHTMLEmail(database *sql.DB, encKey []byte, to, subject, body string) error {
	return sendMail(database, encKey, to, subject, "text/html; charset=UTF-8", body)
}

// TestEmailHTML 生成测试邮件的 HTML（含内嵌 logo）。
func TestEmailHTML() string {
	logo := LogoDataURI()
	return `<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f5f7fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',Arial,sans-serif;">
  <div style="max-width:520px;margin:0 auto;padding:32px 20px;">
    <div style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
      <div style="background:#2563eb;padding:28px 24px;text-align:center;">
        <img src="` + logo + `" alt="CryPtBox" style="width:64px;height:64px;border-radius:14px;background:#ffffff;padding:4px;" />
        <div style="color:#ffffff;font-size:20px;font-weight:700;margin-top:12px;">密匣 CryPtBox</div>
      </div>
      <div style="padding:32px 28px;">
        <h2 style="margin:0 0 16px;font-size:18px;color:#111827;">测试邮件</h2>
        <p style="margin:0 0 12px;font-size:14px;color:#4b5563;line-height:1.7;">这是一封测试邮件，用于验证 SMTP 配置是否正确。</p>
        <p style="margin:0;font-size:14px;color:#4b5563;line-height:1.7;">如果你能正常收到这封邮件，说明 SMTP 配置已生效。</p>
      </div>
      <div style="padding:16px 24px;background:#f9fafb;text-align:center;font-size:12px;color:#9ca3af;">密匣 CryPtBox · 本地优先的密码管理器</div>
    </div>
  </div>
</body>
</html>`
}

// MaxVerifyAttempts 单个验证码允许的最大校验失败次数，超过即作废该验证码。
// 6 位数字验证码的取值空间为 10^6，限制尝试次数是防止在线穷举的关键控制。
const MaxVerifyAttempts = 5

// GenCode 使用密码学安全随机数生成 6 位数字验证码。
func GenCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// hashCode 计算验证码的存储摘要（按 email + purpose 加域隔离），避免明文入库。
// 只需防「拖库后直接读取」这一场景，故使用带上下文的 SHA-256 而非慢哈希。
func hashCode(email, purpose, code string) string {
	sum := sha256.Sum256([]byte(email + "\x00" + purpose + "\x00" + code))
	return hex.EncodeToString(sum[:])
}

// purgeExpiredVerifications 删除所有已过期的验证码记录。
func purgeExpiredVerifications(database *sql.DB) {
	_, _ = database.Exec(`DELETE FROM email_verifications WHERE expires_at <= ?`,
		strconv.FormatInt(time.Now().Unix(), 10))
}

// SaveVerification 保存邮箱验证码（15 分钟有效，expires_at 存 Unix 时间戳，摘要入库）。
// 同一 email + purpose 只保留最新一条，并顺带清理过期记录。
func SaveVerification(database *sql.DB, email, code, purpose string) error {
	purgeExpiredVerifications(database)
	if _, err := database.Exec(`DELETE FROM email_verifications WHERE email = ? AND purpose = ?`, email, purpose); err != nil {
		return err
	}
	expires := strconv.FormatInt(time.Now().Add(15*time.Minute).Unix(), 10)
	_, err := database.Exec(`INSERT INTO email_verifications (email, code, purpose, attempts, expires_at) VALUES (?, ?, ?, 0, ?)`,
		email, hashCode(email, purpose, code), purpose, expires)
	return err
}

// CheckVerification 校验邮箱验证码，并在成功时立即消费，失败时累计尝试次数。
// 一次性消费 + 尝试上限，使验证码无法被重复使用或在线穷举。
func CheckVerification(database *sql.DB, email, code, purpose string) bool {
	if code == "" {
		return false
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	var (
		id       int64
		attempts int
	)
	err := database.QueryRow(
		`SELECT id, attempts FROM email_verifications WHERE email = ? AND purpose = ? AND expires_at > ? ORDER BY id DESC LIMIT 1`,
		email, purpose, now).Scan(&id, &attempts)
	if err != nil {
		return false
	}
	// 已达尝试上限：作废该验证码。
	if attempts >= MaxVerifyAttempts {
		_, _ = database.Exec(`DELETE FROM email_verifications WHERE id = ?`, id)
		return false
	}
	want := hashCode(email, purpose, code)
	// 原子消费：比对与删除在同一条 DELETE 中完成（code 列存的是摘要），
	// 并发请求即便同时通过比对，也只有一个能删到该行，保证严格一次性。
	res, err := database.Exec(`DELETE FROM email_verifications WHERE id = ? AND code = ?`, id, want)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true
	}
	_, _ = database.Exec(`UPDATE email_verifications SET attempts = attempts + 1 WHERE id = ?`, id)
	return false
}

// SendVerifyCode 生成并发送验证码。
func SendVerifyCode(database *sql.DB, encKey []byte, email, purpose string) error {
	code, err := GenCode()
	if err != nil {
		return err
	}
	if err := SaveVerification(database, email, code, purpose); err != nil {
		return err
	}
	subject := "密匣验证码"
	body := "您的验证码是：" + code + "，15 分钟内有效。"
	switch purpose {
	case "reset":
		subject = "密匣密码重置验证码"
		body = "您的密码重置验证码是：" + code + "，15 分钟内有效。"
	case "bind_email":
		subject = "密匣邮箱验证码"
		body = "您正在为账号绑定此邮箱，验证码是：" + code + "，15 分钟内有效。若非本人操作请忽略。"
	}
	return SendEmail(database, encKey, email, subject, body)
}
