package auth

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
)

// 本地最小 SMTP 服务器：记录客户端发来的原始 DATA 报文，用于实测发送链路。
type captureSMTPServer struct {
	ln   net.Listener
	mu   sync.Mutex
	raw  string
	cmds []string
}

func startCaptureSMTP(t *testing.T) *captureSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &captureSMTPServer{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *captureSMTPServer) serve(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	w.WriteString("220 localhost ESMTP\r\n")
	w.Flush()
	inData := false
	var dataBuf strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if inData {
			if line == ".\r\n" || line == ".\n" {
				inData = false
				s.mu.Lock()
				s.raw = dataBuf.String()
				s.mu.Unlock()
				w.WriteString("250 ok\r\n")
				w.Flush()
				continue
			}
			dataBuf.WriteString(line)
			continue
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, strings.TrimRight(line, "\r\n"))
		s.mu.Unlock()
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w.WriteString("250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
		case strings.HasPrefix(up, "HELO"):
			w.WriteString("250 localhost\r\n")
		case strings.HasPrefix(up, "AUTH"):
			w.WriteString("235 ok\r\n")
		case strings.HasPrefix(up, "MAIL"):
			w.WriteString("250 ok\r\n")
		case strings.HasPrefix(up, "RCPT"):
			w.WriteString("250 ok\r\n")
		case strings.HasPrefix(up, "DATA"):
			inData = true
			w.WriteString("354 go ahead\r\n")
		case strings.HasPrefix(up, "QUIT"):
			w.WriteString("221 bye\r\n")
			w.Flush()
			return
		default:
			w.WriteString("250 ok\r\n")
		}
		w.Flush()
	}
}

func (s *captureSMTPServer) Raw() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.raw
}

func (s *captureSMTPServer) Addr() (string, int) {
	host, portStr, _ := net.SplitHostPort(s.ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

// TestSMTPRawMessage 实测 sendMailWithConfig 输出的原始报文，
// 检查中文主题/头部是否符合 RFC（编码、Date 等）。
func TestSMTPRawMessage(t *testing.T) {
	srv := startCaptureSMTP(t)
	host, port := srv.Addr()
	cfg := SMTPConfig{Host: host, Port: port, Username: "u@example.com", Password: "p", From: "u@example.com", SSL: false}
	if err := sendMailWithConfig(cfg, "to@example.com", "密匣验证码", "text/plain; charset=UTF-8", "您的验证码是：123456"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	raw := srv.Raw()
	t.Logf("=== RAW MESSAGE ===\n%s\n=== END ===", raw)
	// 断言：Subject 必须做 RFC 2047 编码（含非 ASCII 时不得裸传）
	var subjectLine string
	for _, l := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(l, "Subject:") {
			subjectLine = l
		}
	}
	if subjectLine == "" {
		t.Fatalf("未找到 Subject 头")
	}
	t.Logf("Subject 头: %q", subjectLine)
	if !strings.Contains(subjectLine, "=?UTF-8?") {
		t.Errorf("Subject 未做 RFC 2047 编码，中文主题裸传（严格 SMTP 服务器会拒收或乱码）")
	}
	if !strings.Contains(raw, "Date:") {
		t.Errorf("报文缺少 Date 头（RFC 5322 要求，部分服务器拒收）")
	}
	if !strings.Contains(raw, "Message-ID:") {
		t.Errorf("报文缺少 Message-ID 头")
	}
	// 正文应为 base64（Content-Transfer-Encoding: base64），保证中文/HTML 无损投递。
	if !strings.Contains(raw, "Content-Transfer-Encoding: base64") {
		t.Errorf("正文未使用 base64 传输编码")
	}
}

// TestSMTPHeaderInjectionSanitized 验证头部注入被清洗（CRLF 被剥离）。
func TestSMTPHeaderInjectionSanitized(t *testing.T) {
	srv := startCaptureSMTP(t)
	host, port := srv.Addr()
	cfg := SMTPConfig{Host: host, Port: port, Username: "u@example.com", Password: "p", From: "u@example.com"}
	if err := sendMailWithConfig(cfg, "to@example.com", "Hi\r\nBcc: evil@example.com", "text/plain; charset=UTF-8", "body"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	// 注入的 CRLF 已被剥离：不得出现以 Bcc: 开头的独立头部行。
	for _, l := range strings.Split(srv.Raw(), "\r\n") {
		if strings.HasPrefix(l, "Bcc:") {
			t.Errorf("头部注入未被清洗：出现独立 Bcc 头 %q", l)
		}
	}
}

// TestSMTPSendRequiresPassword 验证缺少口令时给出明确错误，而非模糊的「认证失败」。
func TestSMTPSendRequiresPassword(t *testing.T) {
	cfg := SMTPConfig{Host: "127.0.0.1", Port: 25, Username: "u@example.com", Password: "", From: "u@example.com"}
	err := sendMailWithConfig(cfg, "to@example.com", "s", "text/plain", "b")
	if err == nil || !strings.Contains(err.Error(), "口令") {
		t.Errorf("缺少口令应返回明确错误，实际: %v", err)
	}
}
