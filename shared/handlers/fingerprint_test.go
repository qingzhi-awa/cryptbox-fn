package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/qingzhi-awa/cryptbox/shared/config"
	"github.com/qingzhi-awa/cryptbox/shared/db"
	"github.com/qingzhi-awa/cryptbox/shared/tlsutil"
)

// TestFingerprintEndpoint 校验 GET /api/fingerprint（PT-02 配套接口）：
//   - 未启用 TLS → 404；
//   - 启用 TLS → 返回与证书实际一致的 SHA-256 指纹（整证书 / SPKI 两种）。
func TestFingerprintEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()

	// 1) 未启用 TLS：应 404。
	{
		cfg := config.Config{JWTSecret: "unit-test-jwt-secret", DBDSN: filepath.Join(dir, "a.db")}
		database, err := db.Open(cfg)
		if err != nil {
			t.Fatalf("open db: %v", err)
		}
		r := gin.New()
		RegisterRoutes(r, cfg, database, nil)
		code, _ := doJSON(t, r, http.MethodGet, "/api/fingerprint", "", nil)
		if code != http.StatusNotFound {
			t.Fatalf("未启用 TLS 时 /api/fingerprint 应为 404，实际 %d", code)
		}
		database.Close()
	}

	// 2) 启用 TLS：返回指纹且与证书一致。
	crt, key, _, err := tlsutil.EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	wantCert, wantSPKI, err := tlsutil.Fingerprints(crt)
	if err != nil {
		t.Fatalf("fingerprints: %v", err)
	}
	cfg := config.Config{
		JWTSecret: "unit-test-jwt-secret",
		DBDSN:     filepath.Join(dir, "b.db"),
		TLSCert:   crt,
		TLSKey:    key,
	}
	database, err := db.Open(cfg)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()
	r := gin.New()
	RegisterRoutes(r, cfg, database, nil)

	code, resp := doJSON(t, r, http.MethodGet, "/api/fingerprint", "", nil)
	if code != http.StatusOK {
		t.Fatalf("/api/fingerprint 应 200，实际 %d resp=%v", code, resp)
	}
	if got, _ := resp["fingerprint"].(string); got != wantCert {
		t.Fatalf("整证书指纹不一致：接口=%q 期望=%q", got, wantCert)
	}
	if got, _ := resp["spki"].(string); got != wantSPKI {
		t.Fatalf("SPKI 指纹不一致：接口=%q 期望=%q", got, wantSPKI)
	}
	if algo, _ := resp["algorithm"].(string); algo != "SHA-256" {
		t.Fatalf("算法标识应为 SHA-256，实际 %q", algo)
	}
	_ = os.RemoveAll(dir)
}
