// Package policy 实现 Sentinel 的策略匹配引擎。
//
// 决策顺序与 bpf/sentinel.bpf.c 中 sentinel_connect4 严格一致：
//   1. 拒绝列表           → DENY
//   2. 临时放行（已审批）  → ALLOW（人工审批优先于污点判定）
//   3. 进程已污染          → NEED_REVIEW（无论目标是否在允许列表）
//   4. 永久允许列表        → ALLOW
//   5. 未知目标            → NEED_REVIEW（deny-by-default）
//
// 审批采用异步模型：Evaluate 只做判定；判定为 NEED_REVIEW 时由守护进程
// 冻结目标进程并调用 approvalSink 提交审批，审批结果通过 AddTempAllow
// 回流（写临时放行 + 同步内核 map）。事件读取循环绝不被审批阻塞。
package policy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sentinel-sec/sentinel/internal/events"
)

// MapSync 把用户态的列表变更同步到内核 BPF map。
// 由 loader 实现；dry-run 模式下为 nil（仅维护用户态列表）。
type MapSync interface {
	SetAllow(ip4 uint32, port uint16, on bool) error
	SetDeny(ip4 uint32, port uint16, on bool) error
	SetTempAllow(ip4 uint32, port uint16, on bool) error
}

// Options 是引擎的构造参数。
type Options struct {
	// TempAllowTTL 是审批通过后临时放行条目的有效期。
	TempAllowTTL time.Duration

	// MapSync 可选；提供时列表变更会同步内核 map。
	MapSync MapSync

	// Logger 可选日志回调。
	Logger func(string)
}

// Engine 是策略匹配引擎的核心结构。
type Engine struct {
	mu         sync.RWMutex
	allowList  map[string]struct{}
	denyList   map[string]struct{}
	tempAllow  map[string]tempEntry
	taintCache map[uint32]uint32

	tempTTL time.Duration
	sync    MapSync
	logger  func(string)

	// approvalSink 由守护进程注入（approval.Manager.Submit），
	// 引擎自身不依赖 approval 包，避免 import 环。
	approvalSink func(ApprovalRequest)
}

// tempEntry 是临时放行列表中的条目。
type tempEntry struct {
	expiresAt time.Time
}

// ApprovalRequest 是发送给审批通道的请求。
type ApprovalRequest struct {
	RequestID   string    // 唯一请求 ID
	Pid         uint32    // 发起连接的进程 tgid
	Comm        string    // 进程名
	DstIP       string    // 目标 IP（点分十进制）
	DstPort     uint16    // 目标端口
	Taint       uint32    // 污点状态
	Description string    // 人类可读描述
	Timestamp   time.Time // 请求时间
}

// NewEngine 创建策略引擎实例。
func NewEngine(opts Options) *Engine {
	logger := opts.Logger
	if logger == nil {
		logger = func(string) {}
	}
	ttl := opts.TempAllowTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Engine{
		allowList:  make(map[string]struct{}),
		denyList:   make(map[string]struct{}),
		tempAllow:  make(map[string]tempEntry),
		taintCache: make(map[uint32]uint32),
		tempTTL:    ttl,
		sync:       opts.MapSync,
		logger:     logger,
	}
}

// SetMapSync 设置（或清除）内核 map 同步器。
func (e *Engine) SetMapSync(s MapSync) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sync = s
}

// SetApprovalSink 设置异步审批提交函数。
func (e *Engine) SetApprovalSink(fn func(ApprovalRequest)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.approvalSink = fn
}

// SubmitApproval 把 NEED_REVIEW 判定推进审批通道（非阻塞）。
// 返回 false 表示没有可用的审批通道（保守处理为拒绝）。
func (e *Engine) SubmitApproval(req ApprovalRequest) bool {
	e.mu.RLock()
	sink := e.approvalSink
	e.mu.RUnlock()
	if sink == nil {
		e.logger("[policy] 无审批通道，默认拒绝")
		return false
	}
	sink(req)
	return true
}

// NewRequestID 生成审批请求 ID。
func NewRequestID(pid uint32, t time.Time) string {
	return fmt.Sprintf("req-%d-%d", pid, t.UnixNano())
}

// AddAllow 向允许列表添加条目并同步内核 map。
func (e *Engine) AddAllow(ip string, port uint16) error {
	ip4, err := ipToU32(ip)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.allowList[listKey(ip, port)] = struct{}{}
	sync := e.sync
	e.mu.Unlock()

	e.logger(fmt.Sprintf("[policy] 允许列表添加: %s", listKey(ip, port)))
	if sync != nil {
		if err := sync.SetAllow(ip4, port, true); err != nil {
			return fmt.Errorf("同步内核 allow_map 失败: %w", err)
		}
	}
	return nil
}

// RemoveAllow 从允许列表移除条目。
func (e *Engine) RemoveAllow(ip string, port uint16) error {
	ip4, err := ipToU32(ip)
	if err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.allowList, listKey(ip, port))
	sync := e.sync
	e.mu.Unlock()

	if sync != nil {
		if err := sync.SetAllow(ip4, port, false); err != nil {
			return fmt.Errorf("同步内核 allow_map 失败: %w", err)
		}
	}
	return nil
}

// AddDeny 向拒绝列表添加条目并同步内核 map。
func (e *Engine) AddDeny(ip string, port uint16) error {
	ip4, err := ipToU32(ip)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.denyList[listKey(ip, port)] = struct{}{}
	sync := e.sync
	e.mu.Unlock()

	e.logger(fmt.Sprintf("[policy] 拒绝列表添加: %s", listKey(ip, port)))
	if sync != nil {
		if err := sync.SetDeny(ip4, port, true); err != nil {
			return fmt.Errorf("同步内核 deny_map 失败: %w", err)
		}
	}
	return nil
}

// RemoveDeny 从拒绝列表移除条目。
func (e *Engine) RemoveDeny(ip string, port uint16) error {
	ip4, err := ipToU32(ip)
	if err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.denyList, listKey(ip, port))
	sync := e.sync
	e.mu.Unlock()

	if sync != nil {
		if err := sync.SetDeny(ip4, port, false); err != nil {
			return fmt.Errorf("同步内核 deny_map 失败: %w", err)
		}
	}
	return nil
}

// AddTempAllow 写入临时放行（审批通过后调用）并同步内核 map。
// Agent 重试连接时内核 temp_allow_map 命中即放行。
func (e *Engine) AddTempAllow(ip string, port uint16, ttl time.Duration) error {
	ip4, err := ipToU32(ip)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = e.tempTTL
	}
	e.mu.Lock()
	e.tempAllow[listKey(ip, port)] = tempEntry{expiresAt: time.Now().Add(ttl)}
	sync := e.sync
	e.mu.Unlock()

	e.logger(fmt.Sprintf("[policy] 临时放行添加: %s (TTL=%v)", listKey(ip, port), ttl))
	if sync != nil {
		if err := sync.SetTempAllow(ip4, port, true); err != nil {
			return fmt.Errorf("同步内核 temp_allow_map 失败: %w", err)
		}
	}
	return nil
}

// RemoveTempAllow 移除临时放行条目（含内核 map）。
func (e *Engine) RemoveTempAllow(ip string, port uint16) error {
	ip4, err := ipToU32(ip)
	if err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.tempAllow, listKey(ip, port))
	sync := e.sync
	e.mu.Unlock()

	if sync != nil {
		if err := sync.SetTempAllow(ip4, port, false); err != nil {
			return fmt.Errorf("同步内核 temp_allow_map 失败: %w", err)
		}
	}
	return nil
}

// Evaluate 对一个连接事件做策略判定（纯判定，无副作用）。
// 决策顺序与内核 sentinel_connect4 一致，见包注释。
func (e *Engine) Evaluate(evt *events.ConnectEvent) uint32 {
	ip := intToIP(evt.DstIP4)
	port := evt.DstPort
	key := listKey(ip, port)

	// 污点状态：优先取内核事件自带的连接时刻快照，其次用户态缓存
	taint := evt.Taint
	if taint == events.TaintClean {
		e.mu.RLock()
		taint = e.taintCache[evt.Pid]
		e.mu.RUnlock()
	}

	e.mu.RLock()
	_, denied := e.denyList[key]
	temp, hasTemp := e.tempAllow[key]
	_, allowed := e.allowList[key]
	e.mu.RUnlock()

	// 1. 拒绝列表优先级最高
	if denied {
		e.logger(fmt.Sprintf("[policy] 拒绝列表命中: %s (pid=%d)", key, evt.Pid))
		return events.DecisionDeny
	}

	// 2. 临时放行（人工审批已通过，优先于污点判定）
	if hasTemp && time.Now().Before(temp.expiresAt) {
		e.logger(fmt.Sprintf("[policy] 临时放行命中: %s (pid=%d)", key, evt.Pid))
		return events.DecisionAllow
	}

	// 3. 已污染进程 → 强制审批
	if taint == events.TaintDirty {
		e.logger(fmt.Sprintf("[policy] 已污染进程请求连接 %s (pid=%d) → 强制审批", key, evt.Pid))
		return events.DecisionNeedReview
	}

	// 4. 干净进程 + 允许列表 → 自动放行
	if allowed {
		e.logger(fmt.Sprintf("[policy] 自动放行: %s (pid=%d)", key, evt.Pid))
		return events.DecisionAllow
	}

	// 5. 未知目标 → 需要审批
	e.logger(fmt.Sprintf("[policy] 未知目标 %s (pid=%d) → 需要审批", key, evt.Pid))
	return events.DecisionNeedReview
}

// UpdateTaintCache 更新污点缓存（从 eBPF taint 事件镜像）。
func (e *Engine) UpdateTaintCache(pid uint32, state uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.taintCache[pid] = state
}

// CleanExpiredTemp 清理过期的临时放行条目（用户态 + 内核 map）。
func (e *Engine) CleanExpiredTemp() {
	now := time.Now()

	type removed struct {
		ip   string
		port uint16
	}
	var expired []removed

	e.mu.Lock()
	for key, entry := range e.tempAllow {
		if now.After(entry.expiresAt) {
			if ip, port, ok := parseListKey(key); ok {
				expired = append(expired, removed{ip: ip, port: port})
			}
			delete(e.tempAllow, key)
		}
	}
	sync := e.sync
	e.mu.Unlock()

	if sync != nil {
		for _, r := range expired {
			if ip4, err := ipToU32(r.ip); err == nil {
				if err := sync.SetTempAllow(ip4, r.port, false); err != nil {
					e.logger(fmt.Sprintf("[policy] 清理内核临时放行失败 %s:%d: %v", r.ip, r.port, err))
				}
			}
			e.logger(fmt.Sprintf("[policy] 临时放行过期清理: %s:%d", r.ip, r.port))
		}
	}
}

// GetAllowList 返回允许列表的副本。
func (e *Engine) GetAllowList() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return copyKeys(e.allowList)
}

// GetDenyList 返回拒绝列表的副本。
func (e *Engine) GetDenyList() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return copyKeys(e.denyList)
}

// GetTempAllow 返回未过期的临时放行列表（含到期时间）。
func (e *Engine) GetTempAllow() []TempAllowEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TempAllowEntry, 0, len(e.tempAllow))
	for k, v := range e.tempAllow {
		if ip, port, ok := parseListKey(k); ok {
			out = append(out, TempAllowEntry{IP: ip, Port: port, ExpiresAt: v.expiresAt})
		}
	}
	return out
}

// TempAllowEntry 描述一条临时放行。
type TempAllowEntry struct {
	IP        string
	Port      uint16
	ExpiresAt time.Time
}

func copyKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func listKey(ip string, port uint16) string {
	return ip + ":" + strconv.Itoa(int(port))
}

func parseListKey(key string) (string, uint16, bool) {
	ip, portStr, err := net.SplitHostPort(key)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, false
	}
	return ip, uint16(port), true
}

// ipToU32 将点分十进制 IPv4 转为网络字节序 uint32（与内核 user_ip4 一致）。
func ipToU32(ip string) (uint32, error) {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return 0, fmt.Errorf("无效 IP 地址: %q", ip)
	}
	v4 := netIP.To4()
	if v4 == nil {
		return 0, fmt.Errorf("仅支持 IPv4: %q", ip)
	}
	return binary.BigEndian.Uint32(v4), nil
}

// intToIP 将网络字节序 uint32 转为点分十进制字符串。
func intToIP(ip4 uint32) string {
	return net.IPv4(
		byte(ip4&0xff),
		byte((ip4>>8)&0xff),
		byte((ip4>>16)&0xff),
		byte((ip4>>24)&0xff),
	).String()
}
