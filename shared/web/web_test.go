package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// R9-06 回归（1/2）：CSP 不得放行 'unsafe-eval'，也不得放行内联脚本。
//
// 背景：vue-i18n 默认走 "生成函数源码 + new Function 求值" 的编译路径，需要 CSP 放行
// 'unsafe-eval'。R9-06 已在 vite.config.js 中固定 `__INTLIFY_JIT_COMPILATION__ = true`，
// 使其改用内置 AST 解释器（无需 eval），因此 CSP 可以收紧到仅 'self'。
func TestContentSecurityPolicyForbidsEval(t *testing.T) {
	if strings.Contains(ContentSecurityPolicy, "unsafe-eval") {
		t.Fatalf("CSP 仍放行 'unsafe-eval'：%s", ContentSecurityPolicy)
	}
	if !strings.Contains(ContentSecurityPolicy, "script-src 'self'") {
		t.Fatalf("CSP 缺少 `script-src 'self'`：%s", ContentSecurityPolicy)
	}
	if strings.Contains(ContentSecurityPolicy, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("CSP 不应为 script-src 放行 'unsafe-inline'：%s", ContentSecurityPolicy)
	}
	if !strings.Contains(ContentSecurityPolicy, "default-src 'self'") {
		t.Fatalf("CSP 缺少 `default-src 'self'`：%s", ContentSecurityPolicy)
	}
}

// 动态求值模式：`new Function(...)` 与 `eval(...)`（允许中间空白）。
var (
	reNewFunction = regexp.MustCompile(`new\s+Function\s*\(`)
	reEvalCall    = regexp.MustCompile(`\beval\s*\(`)
)

// R9-06 回归（2/2）：内嵌的前端产物不得包含任何动态求值调用。
//
// 这是"收紧 CSP 后前端仍能工作"的静态保证：若将来某个依赖（重新）引入 new Function/eval，
// 在浏览器中会被收紧后的 CSP 直接拦断，本测试会在构建/CI 阶段提前失败并定位到具体文件。
func TestEmbeddedBundleHasNoDynamicEval(t *testing.T) {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		t.Fatalf("定位内嵌 dist 失败: %v", err)
	}
	checked := 0
	err = fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(p, ".js") {
			return nil
		}
		b, readErr := fs.ReadFile(dist, p)
		if readErr != nil {
			return readErr
		}
		checked++
		s := string(b)
		if m := reNewFunction.FindString(s); m != "" {
			t.Errorf("%s 含动态求值 %q；CSP 已禁用 eval，构建产物不应依赖它", p, m)
		}
		if m := reEvalCall.FindString(s); m != "" {
			t.Errorf("%s 含动态求值 %q；CSP 已禁用 eval，构建产物不应依赖它", p, m)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历内嵌 dist 失败: %v", err)
	}
	if checked == 0 {
		t.Fatal("未找到任何内嵌 JS 产物，内嵌 dist 可能未构建")
	}
}
