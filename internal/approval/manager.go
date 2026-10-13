// Package approval 实现审批通道，独立于被监控进程和 Agent 对话模型。
//
// 设计原则（来自产品规格）：
//   - 审批请求不经过 Agent 的对话模型
//   - 直接推送到用户的设备
//   - 被污染的模型无法伪造审批请求（API 鉴权由 internal/api 负责）
//   - 对话记录不是审批的传输通道
//
// 本包只包含审批状态机，不含 HTTP 层（见 internal/api）。
// Submit 是非阻塞的：请求进入待审队列并启动超时计时器，
// 审批结果通过 Results 通道异步回流，绝不阻塞事件读取循环。
package approval

import (
	"fmt"
	"sync"
	"time"

	"github.com/sentinel-sec/sentinel/internal/policy"
)

// Manager 管理审批状态机。
type Manager struct {
	mu      sync.Mutex
	pending map[string]*pendingRequest

	notify  chan policy.ApprovalRequest
	results chan Result

	timeout  time.Duration
	autoDeny bool
	logger   func(string)
}

// pendingRequest 是等待审批的请求。
type pendingRequest struct {
	req   policy.ApprovalRequest
	timer *time.Timer
}

// Result 是一次审批的最终结果（含原始请求，便于回流处理）。
type Result struct {
	RequestID string
	Approved  bool
	TimedOut  bool
	Timestamp time.Time
	Request   policy.ApprovalRequest
}

// Card 是推送给用户的审批卡片（JSON 格式）。
type Card struct {
	RequestID   string `json:"request_id"`
	ProcessName string `json:"process_name"`
	PID         uint32 `json:"pid"`
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
	Tainted     bool   `json:"tainted"`
	Timestamp   string `json:"timestamp"`
	Status      string `json:"status"` // "pending"
}

// NewManager 创建审批管理器。
// timeout 为单次审批的超时时间；autoDeny 为 true 时超时自动拒绝。
func NewManager(timeout time.Duration, autoDeny bool, logger func(string)) *Manager {
	if logger == nil {
		logger = func(string) {}
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Manager{
		pending:  make(map[string]*pendingRequest),
		notify:   make(chan policy.ApprovalRequest, 64),
		results:  make(chan Result, 256),
		timeout:  timeout,
		autoDeny: autoDeny,
		logger:   logger,
	}
}

// Submit 登记一条审批请求（非阻塞）。
// RequestID 为空时自动生成。重复 ID 会被拒绝。
func (m *Manager) Submit(req policy.ApprovalRequest) error {
	if req.RequestID == "" {
		req.RequestID = policy.NewRequestID(req.Pid, time.Now())
	}
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now()
	}

	m.mu.Lock()
	if _, dup := m.pending[req.RequestID]; dup {
		m.mu.Unlock()
		return fmt.Errorf("审批请求已存在: %s", req.RequestID)
	}
	p := &pendingRequest{req: req}
	if m.autoDeny {
		id := req.RequestID
		p.timer = time.AfterFunc(m.timeout, func() {
			m.resolveTimeout(id)
		})
	}
	m.pending[req.RequestID] = p
	m.mu.Unlock()

	m.logger(fmt.Sprintf("[approval] 收到审批请求: %s", req.Description))

	// 推送通知（非阻塞，通道满则丢弃，待审列表仍可查询）
	select {
	case m.notify <- req:
	default:
		m.logger("[approval] 通知通道满, 丢弃通知")
	}
	return nil
}

// Approve 处理用户批准操作。
func (m *Manager) Approve(requestID string) error {
	return m.resolveUser(requestID, true)
}

// Deny 处理用户拒绝操作。
func (m *Manager) Deny(requestID string) error {
	return m.resolveUser(requestID, false)
}

func (m *Manager) resolveUser(requestID string, approved bool) error {
	m.mu.Lock()
	p, ok := m.pending[requestID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("审批请求不存在或已处理: %s", requestID)
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	delete(m.pending, requestID)
	req := p.req
	m.mu.Unlock()

	m.emit(Result{
		RequestID: requestID,
		Approved:  approved,
		Timestamp: time.Now(),
		Request:   req,
	})
	if approved {
		m.logger(fmt.Sprintf("[approval] 用户批准: %s", requestID))
	} else {
		m.logger(fmt.Sprintf("[approval] 用户拒绝: %s", requestID))
	}
	return nil
}

// resolveTimeout 处理超时（自动拒绝）。
func (m *Manager) resolveTimeout(requestID string) {
	m.mu.Lock()
	p, ok := m.pending[requestID]
	if !ok {
		m.mu.Unlock()
		return
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	delete(m.pending, requestID)
	req := p.req
	m.mu.Unlock()

	m.emit(Result{
		RequestID: requestID,
		Approved:  false,
		TimedOut:  true,
		Timestamp: time.Now(),
		Request:   req,
	})
	m.logger(fmt.Sprintf("[approval] 审批超时, 自动拒绝: %s", requestID))
}

// emit 非阻塞发送结果；通道满时记日志丢弃（守护进程应为常驻消费者）。
func (m *Manager) emit(r Result) {
	select {
	case m.results <- r:
	default:
		m.logger("[approval] 结果通道满, 结果被丢弃")
	}
}

// PendingCards 返回所有待审批请求的卡片。
func (m *Manager) PendingCards() []Card {
	m.mu.Lock()
	defer m.mu.Unlock()

	cards := make([]Card, 0, len(m.pending))
	for _, p := range m.pending {
		cards = append(cards, Card{
			RequestID:   p.req.RequestID,
			ProcessName: p.req.Comm,
			PID:         p.req.Pid,
			Destination: fmt.Sprintf("%s:%d", p.req.DstIP, p.req.DstPort),
			Reason:      p.req.Description,
			Tainted:     p.req.Taint == 1,
			Timestamp:   p.req.Timestamp.Format(time.RFC3339),
			Status:      "pending",
		})
	}
	return cards
}

// PendingCount 返回待审批数量。
func (m *Manager) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}

// PendingChannel 返回新请求通知通道（用于外部消费者）。
func (m *Manager) PendingChannel() <-chan policy.ApprovalRequest {
	return m.notify
}

// Results 返回审批结果通道。守护进程必须消费此通道。
func (m *Manager) Results() <-chan Result {
	return m.results
}
