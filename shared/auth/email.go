package auth

import (
	"crypto/tls"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net/smtp"
	"strconv"
	"time"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

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

// LoadSMTPConfig 从 meta 读取 SMTP 配置。
func LoadSMTPConfig(database *sql.DB) SMTPConfig {
	port, _ := strconv.Atoi(db.GetMeta(database, "smtp_port"))
	vendor := db.GetMeta(database, "smtp_vendor")
	if vendor == "" {
		vendor = "qq"
	}
	return SMTPConfig{
		Host:     db.GetMeta(database, "smtp_host"),
		Port:     port,
		Username: db.GetMeta(database, "smtp_username"),
		Password: db.GetMeta(database, "smtp_password"),
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
func SMTPConfigured(database *sql.DB) bool {
	cfg := LoadSMTPConfig(database)
	return cfg.Host != "" && cfg.Port != 0
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

// PasswordMinLength 返回注册密码最小长度（默认 6）。
func PasswordMinLength(database *sql.DB) int {
	if v := db.GetMeta(database, "password_min_length"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 6
}

// ValidatePassword 校验注册密码是否满足要求。
func ValidatePassword(database *sql.DB, password string) error {
	minLen := PasswordMinLength(database)
	if len(password) < minLen {
		return errors.New("密码至少 " + strconv.Itoa(minLen) + " 位")
	}
	if db.GetMeta(database, "password_require_complex") == "true" {
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
	}
	return nil
}

// sendMail 发送邮件（通用，contentType 为 text/plain 或 text/html）。
func sendMail(database *sql.DB, to, subject, contentType, body string) error {
	cfg := LoadSMTPConfig(database)
	if cfg.Host == "" || cfg.Port == 0 {
		return errors.New("SMTP 未配置")
	}
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}
	msg := []byte("From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"\r\n" + body)

	addr := cfg.Host + ":" + strconv.Itoa(cfg.Port)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	if cfg.SSL {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return err
		}
		c, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
		defer c.Close()
		if auth != nil {
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
		if err := c.Mail(from); err != nil {
			return err
		}
		if err := c.Rcpt(to); err != nil {
			return err
		}
		w, err := c.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(msg); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		return c.Quit()
	}
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}

// SendEmail 发送纯文本邮件。
func SendEmail(database *sql.DB, to, subject, body string) error {
	return sendMail(database, to, subject, "text/plain; charset=UTF-8", body)
}

// SendHTMLEmail 发送 HTML 邮件。
func SendHTMLEmail(database *sql.DB, to, subject, body string) error {
	return sendMail(database, to, subject, "text/html; charset=UTF-8", body)
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

// GenCode 生成 6 位数字验证码。
func GenCode() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

// SaveVerification 保存邮箱验证码（15 分钟有效，expires_at 存 Unix 时间戳）。
func SaveVerification(database *sql.DB, email, code, purpose string) error {
	expires := strconv.FormatInt(time.Now().Add(15*time.Minute).Unix(), 10)
	_, err := database.Exec(`INSERT INTO email_verifications (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)`,
		email, code, purpose, expires)
	return err
}

// CheckVerification 校验邮箱验证码。
func CheckVerification(database *sql.DB, email, code, purpose string) bool {
	now := strconv.FormatInt(time.Now().Unix(), 10)
	var n int
	err := database.QueryRow(`SELECT COUNT(1) FROM email_verifications WHERE email = ? AND code = ? AND purpose = ? AND expires_at > ?`,
		email, code, purpose, now).Scan(&n)
	return err == nil && n > 0
}

// SendVerifyCode 生成并发送验证码。
func SendVerifyCode(database *sql.DB, email, purpose string) error {
	code := GenCode()
	if err := SaveVerification(database, email, code, purpose); err != nil {
		return err
	}
	subject := "密匣验证码"
	body := "您的验证码是：" + code + "，15 分钟内有效。"
	if purpose == "reset" {
		subject = "密匣密码重置验证码"
		body = "您的密码重置验证码是：" + code + "，15 分钟内有效。"
	}
	return SendEmail(database, email, subject, body)
}
