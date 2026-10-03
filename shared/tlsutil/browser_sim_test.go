package tlsutil

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// rawGet 在指定连接上发送一个 HTTP/1.1 请求并读回完整响应（含 body）。
// 用于精确模拟浏览器在**同一条 keep-alive 连接**上连续请求的行为。
func rawGet(t *testing.T, conn net.Conn, target string, extraHeaders map[string]string) (int, map[string]string, string) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&b, "Host: %s\r\n", conn.RemoteAddr().String())
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0.0.0 Safari/537.36\r\n")
	b.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
	b.WriteString("Accept-Language: zh-CN,zh;q=0.9\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	for k, v := range extraHeaders {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatalf("write request failed: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line failed: %v", err)
	}
	var code int
	fmt.Sscanf(statusLine, "HTTP/1.1 %d", &code)
	headers := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header failed: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if i := strings.Index(line, ":"); i > 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	var body []byte
	if strings.EqualFold(headers["transfer-encoding"], "chunked") {
		for {
			sizeLine, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("read chunk size failed: %v", err)
			}
			var n int
			fmt.Sscanf(strings.TrimSpace(sizeLine), "%x", &n)
			if n == 0 {
				_, _ = br.ReadString('\n')
				break
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(br, chunk); err != nil {
				t.Fatalf("read chunk failed: %v", err)
			}
			body = append(body, chunk...)
			_, _ = br.ReadString('\n')
		}
	} else if cl := headers["content-length"]; cl != "" {
		var n int
		fmt.Sscanf(cl, "%d", &n)
		body = make([]byte, n)
		if _, err := io.ReadFull(br, body); err != nil {
			t.Fatalf("read body failed: %v (want %d bytes)", err, n)
		}
	}
	return code, headers, string(body)
}

// TestBrowserLikeKeepAliveOverDual 模拟浏览器：先取 HTML，解析出资源地址，
// 再在**同一条连接**上取该资源，最后再取一次（连接复用 + 多次请求）。
func TestBrowserLikeKeepAliveOverDual(t *testing.T) {
	plainMux := http.NewServeMux()
	plainMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="/assets/app.js"></script></html>`)
	})
	securedMux := http.NewServeMux()
	securedMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/assets/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `console.log("asset ok");`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><script src="/assets/app.js"></script></html>`)
	})

	crt, key, _, err := EnsureSelfSigned(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ServeDual(ln, crt, key, plainMux, securedMux)
	time.Sleep(200 * time.Millisecond)
	addr := ln.Addr().String()

	// --- HTTPS：同一条连接连续三个请求（HTML / 资源 / 再来一次） ---
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	defer tconn.Close()

	for i, path := range []string{"/", "/assets/app.js", "/assets/app.js?cache=1"} {
		code, headers, body := rawGet(t, tconn, path, map[string]string{"Accept-Encoding": "gzip, deflate"})
		t.Logf("HTTPS keep-alive #%d %s -> %d %s (body %d bytes)", i+1, path, code, headers["content-type"], len(body))
		if code != 200 {
			t.Fatalf("HTTPS request %d to %s returned %d", i+1, path, code)
		}
		if body == "" {
			t.Fatalf("HTTPS request %d to %s returned empty body", i+1, path)
		}
	}

	// --- 明文 HTTP：同一端口 ---
	raw2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw2.Close()
	for i, path := range []string{"/", "/assets/app.js"} {
		code, _, body := rawGet(t, raw2, path, nil)
		t.Logf("PLAIN keep-alive #%d %s -> %d (body %d bytes)", i+1, path, code, len(body))
		if code != 200 || body == "" {
			t.Fatalf("plain request %d failed: %d", i+1, code)
		}
	}

	// --- 并发 6 条 HTTPS 连接（浏览器同源并发上限） ---
	var wg sync.WaitGroup
	errCh := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				errCh <- err
				return
			}
			defer raw.Close()
			c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
			if err := c.Handshake(); err != nil {
				errCh <- err
				return
			}
			for j := 0; j < 3; j++ {
				var b strings.Builder
				fmt.Fprintf(&b, "GET /?concurrent=%d-%d HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n", n, j)
				if _, err := c.Write([]byte(b.String())); err != nil {
					errCh <- err
					return
				}
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					errCh <- fmt.Errorf("conn %d req %d: %v", n, j, err)
					return
				}
				if !strings.Contains(line, "200") {
					errCh <- fmt.Errorf("conn %d req %d got %q", n, j, strings.TrimSpace(line))
					return
				}
				// 丢弃头部与 body
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						errCh <- err
						return
					}
					if strings.TrimSpace(l) == "" {
						break
					}
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("并发连接失败: %v", err)
		}
	}
	t.Log("并发 6 连接 × 3 请求 全部成功")
}
