package tlsutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestServeDual(t *testing.T) {
	dir := t.TempDir()
	crt, key, _, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("PLAIN")) })
	sec := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("SECURE")) })
	go func() {
		_ = ServeDual(ln, crt, key, plain, sec)
	}()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// HTTPS 路径
	resp, err := client.Get("https://127.0.0.1:" + itoa(port) + "/x")
	if err != nil {
		t.Fatalf("HTTPS 请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "SECURE" {
		t.Fatalf("HTTPS 期望 SECURE，实际 %q", body)
	}
	t.Log("HTTPS OK")

	// 明文路径
	resp, err = client.Get("http://127.0.0.1:" + itoa(port) + "/x")
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "PLAIN" {
		t.Fatalf("HTTP 期望 PLAIN，实际 %q", body)
	}
	t.Log("HTTP OK")
}

// TestFingerprints 校验证书指纹计算：格式、长度、自洽性与稳定性。
func TestFingerprints(t *testing.T) {
	dir := t.TempDir()
	crt, _, _, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	certFP, spkiFP, err := Fingerprints(crt)
	if err != nil {
		t.Fatalf("fingerprints: %v", err)
	}
	// SHA-256 → 32 字节 → 95 字符（32*2 + 31 个冒号）
	if len(certFP) != 95 || len(spkiFP) != 95 {
		t.Fatalf("指纹长度应为 95，实际 cert=%d spki=%d", len(certFP), len(spkiFP))
	}
	if certFP == spkiFP {
		t.Fatal("整证书指纹与 SPKI 指纹不应相同")
	}
	for _, fp := range []string{certFP, spkiFP} {
		for i, ch := range fp {
			if (i+1)%3 == 0 {
				if ch != ':' {
					t.Fatalf("第 %d 位应为冒号，实际 %q（%s）", i, ch, fp)
				}
			} else if !(ch >= '0' && ch <= '9') && !(ch >= 'A' && ch <= 'F') {
				t.Fatalf("第 %d 位应为大写十六进制，实际 %q（%s）", i, ch, fp)
			}
		}
	}
	// 同一证书重复计算必须一致（确定性）。
	certFP2, spkiFP2, err := Fingerprints(crt)
	if err != nil || certFP2 != certFP || spkiFP2 != spkiFP {
		t.Fatalf("指纹计算不稳定：%v", err)
	}
	// 独立重算：直接解析证书并用标准库计算，交叉验证。
	raw, _ := os.ReadFile(crt)
	block, _ := pem.Decode(raw)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sum := sha256.Sum256(c.Raw)
	if colonHex(sum[:]) != certFP {
		t.Fatalf("整证书指纹与独立重算不一致")
	}
	t.Logf("certFP=%s… spkiFP=%s…", certFP[:23], spkiFP[:23])
}

// TestFingerprintsBadFile 非法证书文件应返回错误而非 panic。
func TestFingerprintsBadFile(t *testing.T) {
	dir := t.TempDir()
	bad := dir + "/bad.crt"
	if err := os.WriteFile(bad, []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Fingerprints(bad); err == nil {
		t.Fatal("非 PEM 文件应返回错误")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func mustPair(crt, key string) tls.Certificate {
	pair, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		panic(err)
	}
	return pair
}
