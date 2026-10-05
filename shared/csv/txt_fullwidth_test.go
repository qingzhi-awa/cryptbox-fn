package csv

import "testing"

// TestParseTXTEntriesFullWidthColon 锁定「全角冒号分隔符」的字节偏移缺陷。
//
// 回归背景：解析 TXT 时用 strings.IndexAny(line, ":：") 找到分隔符位置，随后按
// line[idx+1:] 取值。全角 '：' 是 UTF-8 三字节字符，idx+1 会切在该字符中间，
// 产出带上两个孤立后继字节的乱码值（Go 按字节切片不 panic，属静默数据损坏）。
// 修复后应按分隔符实际字节长度推进，标题/口令等字段必须完整、无乱码前缀。
func TestParseTXTEntriesFullWidthColon(t *testing.T) {
	cases := []struct {
		name  string
		input string
		field string
		want  string
	}{
		{"半角冒号-标题", "标题: 我的账号\n密码: secret123\n", "title", "我的账号"},
		{"全角冒号-标题", "标题： 我的账号\n密码： secret123\n", "title", "我的账号"},
		{"全角冒号-密码", "标题： 我的账号\n密码： secret123\n", "password", "secret123"},
		{"全角冒号-用户名", "标题： 我的账号\n用户名： alice\n", "username", "alice"},
		{"全角冒号-网址", "标题： 我的账号\n网址： https://example.com\n", "url", "https://example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := ParseTXTEntries([]byte(tc.input))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(entries) == 0 {
				t.Fatalf("未解析出任何条目")
			}
			got := ""
			switch tc.field {
			case "title":
				got = entries[0].Title
			case "password":
				got = entries[0].Password
			case "username":
				got = entries[0].Username
			case "url":
				got = entries[0].URL
			}
			if got != tc.want {
				t.Fatalf("字段 %s = %q, 期望 %q", tc.field, got, tc.want)
			}
		})
	}
}

// TestParseTXTEntriesFullWidthColonNoMojibake 显式守住"不得出现孤立后继字节"这一表征：
// 乱码值会包含 0xBC/0x9A 等 UTF-8 续字节，修复后值必须是合法 UTF-8。
func TestParseTXTEntriesFullWidthColonNoMojibake(t *testing.T) {
	entries, err := ParseTXTEntries([]byte("标题：测试\n密码：p@ss：word\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("未解析出任何条目")
	}
	if entries[0].Title != "测试" {
		t.Fatalf("标题 = %q, 期望 %q（疑似出现孤立续字节乱码）", entries[0].Title, "测试")
	}
	if entries[0].Password != "p@ss：word" {
		t.Fatalf("口令 = %q, 期望 %q（值内的全角冒号应原样保留）", entries[0].Password, "p@ss：word")
	}
}
