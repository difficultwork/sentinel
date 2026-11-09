//go:build linux

package proposal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sentinel-sec/sentinel/internal/approval"
	"github.com/sentinel-sec/sentinel/internal/authd"
)

func TestFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	req := Request{RequestID: "r1", ActionType: ActionInvokeSkill, Target: "gmail", Scope: "read"}
	if err := writeMessage(&buf, &req); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}
	payload, err := readMessage(&buf)
	if err != nil {
		t.Fatalf("readMessage: %v", err)
	}
	if payload == nil {
		t.Fatal("payload 为空")
	}
	// 再读应得 io.EOF(帧被完整消费)
	if _, err := readMessage(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("应读到 io.EOF, got %v", err)
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	var buf bytes.Buffer
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], MaxMessageBytes+1)
	buf.Write(h[:])
	if _, err := readMessage(&buf); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("期望 ErrMessageTooLarge, got %v", err)
	}
}

func TestReadMessageZeroLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})
	if _, err := readMessage(&buf); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("期望 ErrMalformedMessage, got %v", err)
	}
}

func TestEvaluate(t *testing.T) {
	proxy := authd.NewProxy(func(string) {})
	proxy.AddCredential("gmail-oauth", "oauth_token", "secret-value", []string{"gmail.readonly"})

	cases := []struct {
		name string
		req  Request
		want Decision
	}{
		{"缺少 request_id", Request{ActionType: ActionInvokeSkill}, DecisionDeny},
		{"未知动作", Request{RequestID: "r", ActionType: "DO_SOMETHING"}, DecisionDeny},
		{"建连接器需审批", Request{RequestID: "r", ActionType: ActionCreateConnector}, DecisionRequireUserApproval},
		{"只读技能放行", Request{RequestID: "r", ActionType: ActionInvokeSkill, Scope: "read"}, DecisionAllow},
		{"写技能需审批", Request{RequestID: "r", ActionType: ActionInvokeSkill, Scope: "write"}, DecisionRequireUserApproval},
		{"凭证存在放行并发令牌", Request{RequestID: "r", ActionType: ActionRequestCredential, Target: "gmail-oauth"}, DecisionAllow},
		{"凭证不存在拒绝", Request{RequestID: "r", ActionType: ActionRequestCredential, Target: "nope"}, DecisionDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := evaluate(&c.req, proxy, time.Minute)
			if resp.Decision != c.want {
				t.Fatalf("decision = %s, want %s (reason=%s)", resp.Decision, c.want, resp.Reason)
			}
		})
	}

	// 凭证放行必须携带替身令牌
	resp := evaluate(&Request{RequestID: "r", ActionType: ActionRequestCredential, Target: "gmail-oauth"}, proxy, time.Minute)
	if resp.Decision == DecisionAllow && resp.SurrogateToken == "" {
		t.Fatal("ALLOW 且涉及凭证时必须签发替身令牌")
	}

	// 无 authd: 凭证提案拒绝
	resp = evaluate(&Request{RequestID: "r", ActionType: ActionRequestCredential, Target: "x"}, nil, time.Minute)
	if resp.Decision != DecisionDeny {
		t.Fatalf("authd 缺失时凭证提案应 DENY, got %s", resp.Decision)
	}
}

// 端到端: 真实 UDS + SO_PEERCRED(以测试进程自身 uid 作为允许 uid)。
func TestServerEndToEnd(t *testing.T) {
	var logs []string
	logger := func(s string) { logs = append(logs, s) }

	proxy := authd.NewProxy(func(string) {})
	proxy.AddCredential("gmail-oauth", "oauth_token", "v", nil)

	srv, err := NewServer(Deps{
		SocketPath:   t.TempDir() + "/proposal.sock",
		AllowedUIDs:  []uint32{uint32(os.Getuid())},
		Authd:        proxy,
		SurrogateTTL: time.Minute,
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	cases := []struct {
		req  Request
		want Decision
	}{
		{Request{RequestID: "e2e-1", ActionType: ActionInvokeSkill, Scope: "read"}, DecisionAllow},
		{Request{RequestID: "e2e-2", ActionType: ActionCreateConnector}, DecisionRequireUserApproval},
		{Request{RequestID: "e2e-3", ActionType: ActionRequestCredential, Target: "gmail-oauth"}, DecisionAllow},
	}
	for _, c := range cases {
		resp, err := Propose(srv.path, c.req, 5*time.Second)
		if err != nil {
			t.Fatalf("Propose(%s): %v", c.req.RequestID, err)
		}
		if resp.Decision != c.want {
			t.Fatalf("%s: decision=%s want=%s", c.req.RequestID, resp.Decision, c.want)
		}
		if resp.RequestID != c.req.RequestID {
			t.Fatalf("request_id 未回显: %s", resp.RequestID)
		}
	}

	// 审计日志必须包含完整链路且不含令牌明文
	joined := strings.Join(logs, "\n")
	for _, want := range []string{"e2e-1", "decision=ALLOW", "policy=fixed-policy-v1", "uid="} {
		if !strings.Contains(joined, want) {
			t.Fatalf("审计日志缺少 %q:\n%s", want, joined)
		}
	}
	// 替身令牌明文不得出现在日志中
	resp, _ := Propose(srv.path, Request{RequestID: "e2e-4", ActionType: ActionRequestCredential, Target: "gmail-oauth"}, 5*time.Second)
	if resp.SurrogateToken != "" && strings.Contains(joined, resp.SurrogateToken) {
		t.Fatal("审计日志泄露替身令牌明文")
	}
}

// 审批闭环: 需审批的提案 → 落卡(pending 可见, 去重) → approve/deny 后
// 重提案分别获得 ALLOW/DENY; 超时为非裁决, 重提案重新等待审批。
func TestApprovalLoop(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	logger := func(s string) { mu.Lock(); logs = append(logs, s); mu.Unlock() }
	getLogs := func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(logs, "\n") }

	mgr := approval.NewManager(80*time.Millisecond, func(string) {})

	srv, err := NewServer(Deps{
		SocketPath:  t.TempDir() + "/p.sock",
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		Authd:       authd.NewProxy(func(string) {}),
		Approvals:   mgr,
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	// 消费审批结果并路由回提案服务(与 main.go 的结果循环接线一致)
	go func() {
		for res := range mgr.Results() {
			srv.HandleApprovalResult(res)
		}
	}()

	// 1) 首次提案: REQUIRE_USER_APPROVAL + 落卡, reason 带审批请求 ID
	resp, err := Propose(srv.path, Request{RequestID: "a1", ActionType: ActionCreateConnector, Target: "gmail"}, 5*time.Second)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if resp.Decision != DecisionRequireUserApproval {
		t.Fatalf("首次提案应 REQUIRE_USER_APPROVAL, got %s", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "req-") {
		t.Fatalf("reason 应包含审批请求 ID: %s", resp.Reason)
	}
	if mgr.PendingCount() != 1 {
		t.Fatalf("应有 1 张待审卡, got %d", mgr.PendingCount())
	}
	requestID := mgr.PendingCards()[0].RequestID

	// 2) 重复提案: 去重(仍 1 张卡), reason 提示已有待审请求
	resp, _ = Propose(srv.path, Request{RequestID: "a2", ActionType: ActionCreateConnector, Target: "gmail"}, 5*time.Second)
	if resp.Decision != DecisionRequireUserApproval || !strings.Contains(resp.Reason, requestID) {
		t.Fatalf("重复提案应指向同一待审请求: %s", resp.Reason)
	}
	if mgr.PendingCount() != 1 {
		t.Fatalf("重复提案不应新增卡, got %d", mgr.PendingCount())
	}

	// 3) 批准后重提案: ALLOW(记忆)——先等裁决被异步消费
	if err := mgr.Approve(requestID); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	waitForLog(t, getLogs, "用户批准提案")
	resp, _ = Propose(srv.path, Request{RequestID: "a3", ActionType: ActionCreateConnector, Target: "gmail"}, 5*time.Second)
	if resp.Decision != DecisionAllow {
		t.Fatalf("批准后重提案应 ALLOW, got %s", resp.Decision)
	}

	// 4) 拒绝路径: 另一目标 → 卡 → deny → 重提案 DENY
	resp, _ = Propose(srv.path, Request{RequestID: "b1", ActionType: ActionInvokeSkill, Target: "calendar", Scope: "write"}, 5*time.Second)
	if resp.Decision != DecisionRequireUserApproval || mgr.PendingCount() != 1 {
		t.Fatalf("写范围技能应落卡: decision=%s pending=%d", resp.Decision, mgr.PendingCount())
	}
	denyID := mgr.PendingCards()[0].RequestID
	if err := mgr.Deny(denyID); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	waitForLog(t, getLogs, "用户拒绝提案")
	resp, _ = Propose(srv.path, Request{RequestID: "b2", ActionType: ActionInvokeSkill, Target: "calendar", Scope: "write"}, 5*time.Second)
	if resp.Decision != DecisionDeny {
		t.Fatalf("拒绝后重提案应 DENY, got %s", resp.Decision)
	}

	// 5) 超时路径: 非裁决(不记忆), 重提案重新落一张新卡
	resp, _ = Propose(srv.path, Request{RequestID: "c1", ActionType: ActionInvokeSkill, Target: "drive", Scope: "full"}, 5*time.Second)
	if resp.Decision != DecisionRequireUserApproval || mgr.PendingCount() != 1 {
		t.Fatalf("超时用例前置失败: decision=%s pending=%d", resp.Decision, mgr.PendingCount())
	}
	// 轮询等待超时结果被消费(HandleApprovalResult 已清理服务端待审索引)
	waitForLog(t, getLogs, "提案审批超时")
	if mgr.PendingCount() != 0 {
		t.Fatalf("超时后待审卡应被管理器移除, got %d", mgr.PendingCount())
	}
	resp, _ = Propose(srv.path, Request{RequestID: "c2", ActionType: ActionInvokeSkill, Target: "drive", Scope: "full"}, 5*time.Second)
	if resp.Decision != DecisionRequireUserApproval || mgr.PendingCount() != 1 {
		t.Fatalf("超时(非裁决)后重提案应重新落卡: decision=%s pending=%d", resp.Decision, mgr.PendingCount())
	}

	// 6) 闭环日志链完整
	all := getLogs()
	for _, want := range []string{"用户批准提案", "用户拒绝提案", "提案审批超时"} {
		if !strings.Contains(all, want) {
			t.Fatalf("闭环日志缺少 %q:\n%s", want, all)
		}
	}
}

// waitForLog 轮询等待日志中出现指定内容(裁决消费是异步的)。
func waitForLog(t *testing.T, getLogs func() string, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(getLogs(), want) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(getLogs(), want) {
		t.Fatalf("等待日志 %q 超时", want)
	}
}
