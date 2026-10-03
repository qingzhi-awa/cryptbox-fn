// Package tlsutil 提供自签证书的自动生成：让服务端"装完即 HTTPS"。
//
// 设计说明：每个部署实例在首次启动时生成**独立的**自签证书（而非在二进制中
// 内嵌共享证书）。开源项目内嵌共享证书意味着私钥对所有人公开，攻击者可以
// 用它冒充任意实例实施中间人攻击；每实例独立私钥则把"伪造身份"的门槛
// 提高到"需要访问 NAS 本机"。
//
// 自签证书提供：传输加密 + 防被动嗅探。它不能提供浏览器层面的身份验证
// （用户首次访问需接受一次证书警告）；需要真正身份验证时应使用受信 CA
// 签发的正式证书（通过 TLS_CERT/TLS_KEY 或替换数据目录中的证书文件）。
package tlsutil

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Fingerprints 计算证书文件的两类 SHA-256 指纹：
//   - certFP：整张叶子证书 DER 的摘要（浏览器「证书指纹」展示值，客户端据此做固定）；
//   - spkiFP：SubjectPublicKeyInfo 的摘要（跨证书续期保持不变的公钥指纹）。
//
// 返回值为冒号分隔的大写十六进制串（如 AB:CD:…），与浏览器/openssl 的展示格式一致。
func Fingerprints(certPath string) (certFP, spkiFP string, err error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", "", fmt.Errorf("证书文件不是有效的 PEM 格式")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	sumCert := sha256.Sum256(cert.Raw)
	sumSPKI := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return colonHex(sumCert[:]), colonHex(sumSPKI[:]), nil
}

// colonHex 把字节串格式化为冒号分隔的大写十六进制串。
func colonHex(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b)*3 - 1)
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", x)
	}
	return sb.String()
}

// EnsureSelfSigned 确保数据目录中存在一对自签证书，返回证书与私钥路径。
// 已存在时直接返回（不覆盖，保证重启后证书与浏览器已信任的状态一致）。
// 证书 SAN 自动收集本机主机名与全部非环回 IP，覆盖常见的访问方式。
func EnsureSelfSigned(dataDir string) (crtPath, keyPath string, created bool, err error) {
	crtPath = filepath.Join(dataDir, "tls.crt")
	keyPath = filepath.Join(dataDir, "tls.key")
	if _, err := os.Stat(crtPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return crtPath, keyPath, false, nil
		}
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", "", false, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", false, err
	}

	// 120 位随机序列号（X.509 要求证书序列号为正且唯一）。
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 120)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", false, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "CryPtBox self-signed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 年，足够一个部署周期
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames(),
		IPAddresses:           ipAddresses(),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", false, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", false, err
	}

	if err := writePEM(crtPath, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", false, err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", false, err
	}
	return crtPath, keyPath, true, nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func dnsNames() []string {
	names := []string{"localhost"}
	if host, err := os.Hostname(); err == nil && host != "" {
		names = append(names, host)
	}
	return names
}

func ipAddresses() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					ips = append(ips, ipnet.IP)
				}
			}
		}
	}
	return ips
}

// peekConn 包装已 Peek 过首字节的连接，保证后续读取不丢失数据。
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// ServeDual 在同一个 TCP 端口上按连接首字节自动分发 HTTPS / HTTP：
// 首字节 0x16（TLS ClientHello）走 TLS，其余走明文 HTTP。
//
// 这是 NAS/网关场景的关键能力：fnOS 的端口健康检查（checkport）与统一网关
// 的 API 转发使用明文 HTTP，而用户的浏览器使用 HTTPS——同端口双协议让
// 两者互不干扰，浏览器获得加密，网关与探测保持兼容。
func ServeDual(ln net.Listener, certFile, keyFile string, plain, secured http.Handler) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			br := bufio.NewReader(c)
			head, err := br.Peek(1)
			if err != nil {
				c.Close()
				return
			}
			pc := &peekConn{Conn: c, r: br}
			// 单连接的 http.Server：Accept 第二次起阻塞，直到连接被
			// http 层关闭（ConnState=StateClosed）再返回，避免把正在
			// 处理的连接提前关闭。
			sl := newSingleListener(pc)
			var srv *http.Server
			if head[0] == 0x16 {
				tlsConn := tls.Server(pc, tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					c.Close()
					return
				}
				sl.reset(tlsConn)
				srv = &http.Server{
					Handler:           secured,
					ReadHeaderTimeout: 30 * time.Second,
					ConnState: func(c net.Conn, s http.ConnState) {
						if s == http.StateClosed || s == http.StateHijacked {
							sl.close()
						}
					},
				}
			} else {
				srv = &http.Server{
					Handler:           plain,
					ReadHeaderTimeout: 30 * time.Second,
					ConnState: func(c net.Conn, s http.ConnState) {
						if s == http.StateClosed || s == http.StateHijacked {
							sl.close()
						}
					},
				}
			}
			// Serve 返回即连接服务结束；关闭底层连接（幂等）。
			_ = srv.Serve(sl)
			c.Close()
		}(conn)
	}
}

// singleListener 把单个已接受连接伪装成 Listener，供 http.Server.Serve 使用。
// 第一次 Accept 返回连接；之后阻塞直到 close 被调用（由 ConnState=StateClosed
// 触发），保证 http.Server 在连接的整个生命周期内持续运行。
type singleListener struct {
	mu        sync.Mutex
	conn      net.Conn
	done      chan struct{}
	once      sync.Once
	delivered bool
}

func newSingleListener(c net.Conn) *singleListener {
	return &singleListener{conn: c, done: make(chan struct{})}
}

// reset 在 TLS 握手完成后替换为加密连接。
func (l *singleListener) reset(c net.Conn) {
	l.mu.Lock()
	l.conn = c
	l.mu.Unlock()
}

func (l *singleListener) close() {
	l.mu.Lock()
	conn := l.conn
	l.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	l.once.Do(func() { close(l.done) })
}

func (l *singleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	conn, delivered := l.conn, l.delivered
	l.delivered = true
	l.mu.Unlock()
	if delivered {
		// 连接已交付，阻塞到连接服务结束（ConnState=StateClosed 触发 close）。
		<-l.done
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *singleListener) Close() error {
	l.close()
	return nil
}

func (l *singleListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return nil
}

// ForceHTTPSRedirect 把明文 HTTP 请求 301 重定向到同主机的 HTTPS 地址。
// 本机来源（localhost / 127.0.0.1 / ::1）豁免——网关与端口健康检查的
// 明文转发来自本机，必须保持直通。
func ForceHTTPSRedirect(next http.Handler, tlsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLocalHostHost(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
			host = host[:i]
		}
		if tlsPort != "443" {
			host = host + ":" + tlsPort
		}
		http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
	})
}

func isLocalHostHost(host string) bool {
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
}
