package main

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
)

// 最小 SMTP 收集服务器（仅供 -test-smtp 回归测试）：记录收到的命令行。
type captureSMTPServer struct {
	ln   net.Listener
	mu   sync.Mutex
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
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if inData {
			if line == ".\r\n" || line == ".\n" {
				inData = false
				w.WriteString("250 ok\r\n")
				w.Flush()
			}
			continue
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, strings.TrimRight(line, "\r\n"))
		s.mu.Unlock()
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w.WriteString("250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
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

func (s *captureSMTPServer) cmdList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.cmds))
	copy(out, s.cmds)
	return out
}

func (s *captureSMTPServer) addr() (string, string) {
	host, port, _ := net.SplitHostPort(s.ln.Addr().String())
	return host, port
}

// TestRunTestSMTPReadsPasswordFromStdin 验证 R8-05：-test-smtp 的 SMTP 口令来自标准输入，
// 而非命令行参数（argv 仅含 host/port/username/ssl/to）。
//
// 原缺陷：口令经 os.Args 传递，安装期间同机任意用户 `ps` / 读 /proc/<pid>/cmdline 即可拿到，
// 而 SMTP 授权码常与邮箱主口令相同。修复后 args 里已不含口令，且 stdin 的口令被真正用于认证。
func TestRunTestSMTPReadsPasswordFromStdin(t *testing.T) {
	srv := startCaptureSMTP(t)
	host, port := srv.addr()

	const password = "SuperSecretAuthCode"
	// 注意：args 只有 5 个元素，其中不含口令——若实现回退到 argv 取口令，这里会取空/越界。
	args := []string{host, port, "me@qq.com", "false", "me@qq.com"}
	if err := runTestSMTP(args, strings.NewReader(password+"\n")); err != nil {
		t.Fatalf("runTestSMTP 失败: %v", err)
	}

	// AUTH PLAIN 载荷应为 base64("\x00user\x00pass")，其中含 stdin 提供的口令。
	want := base64.StdEncoding.EncodeToString([]byte("\x00me@qq.com\x00" + password))
	found := false
	for _, c := range srv.cmdList() {
		if strings.HasPrefix(strings.ToUpper(c), "AUTH") && strings.Contains(c, want) {
			found = true
		}
	}
	if !found {
		t.Errorf("SMTP 会话未使用 stdin 提供的口令认证；收到的命令: %v", srv.cmdList())
	}
}

// TestRunTestSMTPRequiresArgs 验证参数不足时返回明确错误而非 panic。
func TestRunTestSMTPRequiresArgs(t *testing.T) {
	if err := runTestSMTP([]string{"h", "25", "u"}, strings.NewReader("p\n")); err == nil {
		t.Error("参数不足应返回错误")
	}
	if err := runTestSMTP([]string{"h", "notaport", "u", "false", "to@x"}, strings.NewReader("p\n")); err == nil {
		t.Error("非法端口应返回错误")
	}
}
