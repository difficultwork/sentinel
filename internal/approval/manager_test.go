package approval

import (
	"testing"
	"time"

	"github.com/sentinel-sec/sentinel/internal/policy"
)

func newTestReq(id string) policy.ApprovalRequest {
	return policy.ApprovalRequest{
		RequestID: id,
		Pid:       1234,
		Comm:      "agent",
		DstIP:     "203.0.113.9",
		DstPort:   443,
		Taint:     1,
	}
}

func drainResults(m *Manager) <-chan Result { return m.Results() }

// TestApproveFlow 验证 提交→批准 结果回流。
func TestApproveFlow(t *testing.T) {
	m := NewManager(time.Minute, true, nil)
	results := drainResults(m)

	if err := m.Submit(newTestReq("r1")); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if m.PendingCount() != 1 {
		t.Fatalf("待审数量 = %d", m.PendingCount())
	}

	if err := m.Approve("r1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	select {
	case r := <-results:
		if !r.Approved || r.TimedOut || r.RequestID != "r1" {
			t.Errorf("结果错误: %+v", r)
		}
		if r.Request.Pid != 1234 || r.Request.DstIP != "203.0.113.9" {
			t.Errorf("结果未携带原始请求: %+v", r.Request)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到审批结果")
	}

	if m.PendingCount() != 0 {
		t.Errorf("批准后待审应清零")
	}

	// 重复批准应报错
	if err := m.Approve("r1"); err == nil {
		t.Errorf("重复批准应报错")
	}
}

// TestDenyFlow 验证 提交→拒绝 结果回流。
func TestDenyFlow(t *testing.T) {
	m := NewManager(time.Minute, true, nil)
	results := drainResults(m)

	_ = m.Submit(newTestReq("r2"))
	if err := m.Deny("r2"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	select {
	case r := <-results:
		if r.Approved {
			t.Errorf("应为拒绝: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到审批结果")
	}
}

// TestTimeoutAutoDeny 验证超时自动拒绝。
func TestTimeoutAutoDeny(t *testing.T) {
	m := NewManager(30*time.Millisecond, true, nil)
	results := drainResults(m)

	_ = m.Submit(newTestReq("r3"))

	select {
	case r := <-results:
		if r.Approved || !r.TimedOut {
			t.Errorf("应为超时拒绝: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("超时未触发自动拒绝")
	}
	if m.PendingCount() != 0 {
		t.Errorf("超时后待审应清零")
	}
}

// TestSubmitIsNonBlocking 验证 Submit 不阻塞（无消费者时缓冲不满即返回）。
func TestSubmitIsNonBlocking(t *testing.T) {
	m := NewManager(time.Minute, false, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 32; i++ {
			if err := m.Submit(newTestReq("")); err != nil {
				t.Errorf("Submit: %v", err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit 被阻塞")
	}
}

// TestDuplicateIDRejected 验证重复请求 ID 被拒绝。
func TestDuplicateIDRejected(t *testing.T) {
	m := NewManager(time.Minute, true, nil)
	if err := m.Submit(newTestReq("dup")); err != nil {
		t.Fatal(err)
	}
	if err := m.Submit(newTestReq("dup")); err == nil {
		t.Errorf("重复 ID 应报错")
	}
}

// TestPendingCards 验证卡片字段。
func TestPendingCards(t *testing.T) {
	m := NewManager(time.Minute, true, nil)
	_ = m.Submit(newTestReq("r4"))

	cards := m.PendingCards()
	if len(cards) != 1 {
		t.Fatalf("卡片数 = %d", len(cards))
	}
	c := cards[0]
	if c.RequestID != "r4" || c.ProcessName != "agent" ||
		c.Destination != "203.0.113.9:443" || !c.Tainted || c.Status != "pending" {
		t.Errorf("卡片字段错误: %+v", c)
	}
}
