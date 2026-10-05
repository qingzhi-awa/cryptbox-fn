package handlers

import (
	"fmt"
	"sync"
	"testing"

	"github.com/qingzhi-awa/cryptbox/shared/db"
)

// TestConcurrentUserCreationNoIDCollision 锁定 PT：并发建号不得因用户 id 竞争而失败。
//
// 回归背景：早期 create/register/import 三处都先调用 FindNextUserID（普通 SELECT，
// 无锁、无事务）拿到"下一个可用 id"，再单独 INSERT。两个并发请求会算出同一个 id，
// 后到者因主键冲突返回 500 —— 对合法用户表现为"注册偶发失败"，批量导入时还会
// 中途中断。修复后 CreateUserWithNextID 在冲突时重算重试，任何并发度下都应全部成功。
func TestConcurrentUserCreationNoIDCollision(t *testing.T) {
	_, database := newTestServer(t)

	// 收紧重试次数：本用例验证"并发不再失败"，随机退避足以收敛，无需生产级上限，
	// 否则毫秒级退避 × 大量重试会让用例耗时过长。
	db.SetUserIDRetryBaseForTest(200)
	t.Cleanup(func() { db.SetUserIDRetryBaseForTest(0) })

	const n = 24
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("race_user_%02d", idx)
			_, err := db.CreateUserWithNextID(database, name, "$2a$12$abcdefghijklmnopqrstuv", "user", name+"@example.com", "", "")
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发建号第 %d 个失败（并发 id 竞争未消除）: %v", i, err)
		}
	}

	// 全部创建成功，且 id 唯一。
	var count int
	if err := database.QueryRow(`SELECT COUNT(1) FROM users WHERE username LIKE 'race_user_%'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != n {
		t.Fatalf("期望 %d 个用户，实际 %d", n, count)
	}
	rows, err := database.Query(`SELECT id FROM users WHERE username LIKE 'race_user_%' ORDER BY id`)
	if err != nil {
		t.Fatalf("query ids: %v", err)
	}
	defer rows.Close()
	seen := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		if seen[id] {
			t.Fatalf("出现重复 id：%d", id)
		}
		seen[id] = true
	}
}
