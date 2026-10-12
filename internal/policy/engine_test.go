package policy

import (
	"testing"
	"time"

	"github.com/sentinel-sec/sentinel/internal/events"
)

// mockMapSync 记录内核 map 同步调用，用于断言同步行为。
type mockMapSync struct {
	allowCalls []mapEntry
	denyCalls  []mapEntry
	tempCalls  []mapEntry
}

type mapEntry struct {
	ip4  uint32
	port uint16
	on   bool
}

func (m *mockMapSync) SetAllow(ip4 uint32, port uint16, on bool) error {
	m.allowCalls = append(m.allowCalls, mapEntry{ip4, port, on})
	return nil
}

func (m *mockMapSync) SetDeny(ip4 uint32, port uint16, on bool) error {
	m.denyCalls = append(m.denyCalls, mapEntry{ip4, port, on})
	return nil
}

func (m *mockMapSync) SetTempAllow(ip4 uint32, port uint16, on bool) error {
	m.tempCalls = append(m.tempCalls, mapEntry{ip4, port, on})
	return nil
}

func newTestEngine(sync MapSync) *Engine {
	return NewEngine(Options{
		TempAllowTTL: 5 * time.Minute,
		MapSync:      sync,
	})
}

func ipEvent(ip string, port uint16, pid uint32, taint uint32) events.ConnectEvent {
	ip4 := uint32(0)
	// 与内核一致的网络字节序：低字节是第一段
	for i, b := range []byte(parseDotted(ip)) {
		ip4 |= uint32(b) << (8 * i)
	}
	return events.ConnectEvent{Pid: pid, DstIP4: ip4, DstPort: port, Taint: taint}
}

func parseDotted(ip string) [4]byte {
	var out [4]byte
	var cur, idx int
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			out[idx] = byte(cur)
			cur, idx = 0, idx+1
			continue
		}
		cur = cur*10 + int(ip[i]-'0')
	}
	return out
}

// TestDecisionMatrix 验证决策矩阵与内核 sentinel_connect4 顺序一致：
// deny → temp → dirty → allow → unknown(need review)
func TestDecisionMatrix(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(e *Engine)
		event    events.ConnectEvent
		expected uint32
	}{
		{
			name:  "干净进程+允许列表 → 放行",
			setup: func(e *Engine) { _ = e.AddAllow("10.0.0.1", 443) },
			event: ipEvent("10.0.0.1", 443, 100, events.TaintClean),
			expected: events.DecisionAllow,
		},
		{
			name:  "干净进程+拒绝列表 → 拒绝",
			setup: func(e *Engine) { _ = e.AddDeny("10.0.0.2", 80) },
			event: ipEvent("10.0.0.2", 80, 100, events.TaintClean),
			expected: events.DecisionDeny,
		},
		{
			name:  "污点进程+允许列表 → 需要审批",
			setup: func(e *Engine) { _ = e.AddAllow("10.0.0.1", 443) },
			event: ipEvent("10.0.0.1", 443, 100, events.TaintDirty),
			expected: events.DecisionNeedReview,
		},
		{
			name:  "污点进程+拒绝列表 → 拒绝（拒绝优先于污点）",
			setup: func(e *Engine) { _ = e.AddDeny("10.0.0.2", 80) },
			event: ipEvent("10.0.0.2", 80, 100, events.TaintDirty),
			expected: events.DecisionDeny,
		},
		{
			name:  "干净进程+未知目标 → 需要审批",
			setup: func(e *Engine) {},
			event: ipEvent("203.0.113.9", 443, 100, events.TaintClean),
			expected: events.DecisionNeedReview,
		},
		{
			name: "污点进程+临时放行 → 放行（人工审批优先于污点）",
			setup: func(e *Engine) {
				_ = e.AddTempAllow("10.0.0.1", 443, time.Minute)
			},
			event:    ipEvent("10.0.0.1", 443, 100, events.TaintDirty),
			expected: events.DecisionAllow,
		},
		{
			name: "拒绝列表优先于临时放行",
			setup: func(e *Engine) {
				_ = e.AddDeny("10.0.0.2", 80)
				_ = e.AddTempAllow("10.0.0.2", 80, time.Minute)
			},
			event:    ipEvent("10.0.0.2", 80, 100, events.TaintClean),
			expected: events.DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEngine(nil)
			tt.setup(e)
			if got := e.Evaluate(&tt.event); got != tt.expected {
				t.Errorf("Evaluate() = %d, 期望 %d", got, tt.expected)
			}
		})
	}
}

// TestTempAllowExpiry 验证临时放行 TTL 过期后恢复需审批。
func TestTempAllowExpiry(t *testing.T) {
	e := NewEngine(Options{TempAllowTTL: 20 * time.Millisecond})
	_ = e.AddTempAllow("10.0.0.1", 443, 20*time.Millisecond)

	evt := ipEvent("10.0.0.1", 443, 100, events.TaintClean)
	if got := e.Evaluate(&evt); got != events.DecisionAllow {
		t.Fatalf("TTL 内应放行，得到 %d", got)
	}

	time.Sleep(30 * time.Millisecond)
	if got := e.Evaluate(&evt); got != events.DecisionNeedReview {
		t.Fatalf("TTL 过期后应需要审批，得到 %d", got)
	}
}

// TestMapSyncOnMutations 验证列表变更同步到内核 map。
func TestMapSyncOnMutations(t *testing.T) {
	sync := &mockMapSync{}
	e := newTestEngine(sync)

	_ = e.AddAllow("10.0.0.1", 443)
	_ = e.AddDeny("10.0.0.2", 80)
	_ = e.AddTempAllow("10.0.0.3", 8080, time.Minute)

	if len(sync.allowCalls) != 1 || !sync.allowCalls[0].on {
		t.Errorf("AddAllow 应同步 allow_map: %+v", sync.allowCalls)
	}
	if len(sync.denyCalls) != 1 || !sync.denyCalls[0].on {
		t.Errorf("AddDeny 应同步 deny_map: %+v", sync.denyCalls)
	}
	if len(sync.tempCalls) != 1 || !sync.tempCalls[0].on {
		t.Errorf("AddTempAllow 应同步 temp_allow_map: %+v", sync.tempCalls)
	}

	_ = e.RemoveAllow("10.0.0.1", 443)
	if len(sync.allowCalls) != 2 || sync.allowCalls[1].on {
		t.Errorf("RemoveAllow 应同步删除 allow_map: %+v", sync.allowCalls)
	}
}

// TestCleanExpiredTempSync 验证过期清理同步删除内核 map 条目。
func TestCleanExpiredTempSync(t *testing.T) {
	sync := &mockMapSync{}
	e := newTestEngine(sync)

	_ = e.AddTempAllow("10.0.0.1", 443, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	e.CleanExpiredTemp()

	if len(sync.tempCalls) != 2 {
		t.Fatalf("期望 2 次同步（写入+删除），得到 %d: %+v", len(sync.tempCalls), sync.tempCalls)
	}
	if sync.tempCalls[1].on {
		t.Errorf("过期清理应删除内核条目: %+v", sync.tempCalls[1])
	}
	if len(e.GetTempAllow()) != 0 {
		t.Errorf("过期条目应被清除")
	}
}

// TestTaintCacheFallback 验证事件自带污点优先、缓存兜底。
func TestTaintCacheFallback(t *testing.T) {
	e := newTestEngine(nil)
	_ = e.AddAllow("10.0.0.1", 443)

	evt := ipEvent("10.0.0.1", 443, 200, events.TaintClean)
	e.UpdateTaintCache(200, events.TaintDirty)
	if got := e.Evaluate(&evt); got != events.DecisionNeedReview {
		t.Errorf("缓存污点应触发审批，得到 %d", got)
	}

	// 事件自带 CLEAN、缓存也是 CLEAN → 放行
	e2 := newTestEngine(nil)
	_ = e2.AddAllow("10.0.0.1", 443)
	if got := e2.Evaluate(&evt); got != events.DecisionAllow {
		t.Errorf("干净进程 + 允许列表应放行，得到 %d", got)
	}
}

// TestSubmitApprovalNoSink 验证无审批通道时返回 false。
func TestSubmitApprovalNoSink(t *testing.T) {
	e := newTestEngine(nil)
	if e.SubmitApproval(ApprovalRequest{RequestID: "r1"}) {
		t.Errorf("无审批通道应返回 false")
	}
}
