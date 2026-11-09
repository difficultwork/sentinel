//go:build linux

package proposal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"sentinel/internal/approval"
	"sentinel/internal/authd"
	"sentinel/internal/policy"
)

// 连接级超时(固定值, 不暴露配置): 客户端为每次提案建立短连接即可,
// 长连接也允许, 空闲超过该时长由服务端回收。
const (
	connReadTimeout  = 30 * time.Second
	connWriteTimeout = 10 * time.Second
)

// ucred 是 SO_PEERCRED 返回的内核凭证(稳定 UAPI, 3 个标量)。
// 不用 x/sys 的 GetsockoptUcred: 第三方绑定曾出现过字段漂移
// (见 docs/review-2026-10.md 5.4 节), 对老而稳的 UAPI 直接裸调更可靠。
type ucred struct {
	Pid int32
	Uid uint32
	Gid uint32
}

// peerCred 在 accept() 后立即读取对端内核凭证。
func peerCred(conn net.Conn) (ucred, error) {
	var cred ucred
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return cred, errors.New("proposal: 非 Unix 域连接")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return cred, err
	}
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		clen := uint32(unsafe.Sizeof(cred))
		r1, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd,
			uintptr(unix.SOL_SOCKET), uintptr(unix.SO_PEERCRED),
			uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&clen)), 0)
		if r1 != 0 {
			errno = e
		}
	}); err != nil {
		return cred, err
	}
	if errno != 0 {
		return cred, errno
	}
	return cred, nil
}

// Deps 是提案服务端的依赖。
type Deps struct {
	SocketPath      string            // 套接字路径(绝对路径; 目录需已存在或可创建)
	AllowedUIDs     []uint32          // 允许连接的宿主 UID(SO_PEERCRED 视角)
	Authd           *authd.Proxy      // 可为 nil: 凭证提案将返回 DENY(服务未启用)
	SurrogateTTL    time.Duration     // 替身令牌 TTL
	Approvals       *approval.Manager // 可为 nil: REQUIRE_USER_APPROVAL 只回话不落卡
	Logger          func(string)
}

// Server 是提案通道服务端(监听端, 跑在特权容器)。
type Server struct {
	ln      net.Listener
	path    string
	allowed map[uint32]struct{}
	deps    Deps
	conns   sync.Map // net.Conn -> struct{}; Close 时主动断开, 快速回收
	wg      sync.WaitGroup

	// 审批闭环状态: 决策记忆 + 待审卡去重(键 = uid|action|target)。
	// 语义与出口管控对称: 批准→ALLOW(随守护进程生命周期), 拒绝→DENY,
	// 超时→非裁决(不记忆, 重新提案再次等待审批)。
	//
	// waiters: 同键下等待终局"推送"的连接。裁决落定时由
	// HandleApprovalResult 直接把终局 Response 写回这些连接——
	// 客户端保持连接阻塞读取即可, 无需轮询重提案。
	mu           sync.Mutex
	decisions    map[string]Decision
	pendingCards map[string]string
	waiters      map[string][]*waiter
}

// waiter 是一个等待终局推送的请求(通道缓冲 1, 推送永不阻塞)。
type waiter struct {
	reqID string
	ch    chan Response
}

// pkey 生成提案决策记忆键。
func pkey(uid uint32, action, target string) string {
	return fmt.Sprintf("%d|%s|%s", uid, action, target)
}

// NewServer 校验目录权限、清理残留套接字并开始监听。
// 套接字目录若对全局可写则拒绝启动(防低权限进程抢注/替换套接字文件)。
func NewServer(d Deps) (*Server, error) {
	if !filepath.IsAbs(d.SocketPath) {
		return nil, fmt.Errorf("proposal: socket_path 必须是绝对路径: %s", d.SocketPath)
	}
	if len(d.AllowedUIDs) == 0 {
		return nil, errors.New("proposal: allowed_uids 不能为空(至少一个宿主 UID)")
	}
	dir := filepath.Dir(d.SocketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("proposal: 创建套接字目录失败: %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("proposal: 检查套接字目录失败: %w", err)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("proposal: 套接字目录 %s 对全局可写, 拒绝启动(请收紧目录权限)", dir)
	}

	// 残留清理: 重启后 unlink 旧路径再 bind, 避免 EADDRINUSE
	// (特权容器重启后套接字文件随容器文件系统重建, 这里兜底同容器内的残留)
	if err := os.Remove(d.SocketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("proposal: 清理残留套接字失败: %w", err)
	}
	ln, err := net.Listen("unix", d.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("proposal: 监听 %s 失败: %w", d.SocketPath, err)
	}
	// 第二道防线: 收紧文件权限(真正判定在 SO_PEERCRED)。
	// 属主保持为当前用户(mgmt 内为 root); 需要按 Agent UID 属主化时
	// 由部署脚本 chown, 见 docker/README.md。
	if err := os.Chmod(d.SocketPath, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("proposal: 收紧套接字权限失败: %w", err)
	}

	s := &Server{
		ln:           ln,
		path:         d.SocketPath,
		allowed:      make(map[uint32]struct{}, len(d.AllowedUIDs)),
		deps:         d,
		decisions:    make(map[string]Decision),
		pendingCards: make(map[string]string),
		waiters:      make(map[string][]*waiter),
	}
	for _, uid := range d.AllowedUIDs {
		s.allowed[uid] = struct{}{}
	}
	if d.Logger != nil {
		d.Logger(fmt.Sprintf("[proposal] 提案通道已监听: %s(UDS+SO_PEERCRED, 不触发 connect4/6 网络钩子)", d.SocketPath))
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Close 停止监听、主动断开在途连接并等待处理完毕, 最后移除套接字文件。
func (s *Server) Close() {
	s.ln.Close()
	s.conns.Range(func(k, _ any) bool {
		if c, ok := k.(net.Conn); ok {
			c.Close()
		}
		return true
	})
	s.wg.Wait()
	os.Remove(s.path)
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener 已关闭
		}
		s.conns.Store(conn, struct{}{})
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn 处理一条连接: 先鉴权后读体, 支持同一连接多次提案。
func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer s.conns.Delete(conn)

	// 鉴权在任何应用层读取之前完成; 内核身份是唯一依据。
	cred, err := peerCred(conn)
	if err != nil {
		s.audit(cred, "-", DecisionDeny, fmt.Sprintf("读取对端凭证失败: %v", err))
		return
	}
	if _, ok := s.allowed[cred.Uid]; !ok {
		// 身份不符: 不读取请求体, 直接断开
		s.audit(cred, "-", DecisionDeny, "身份不符: uid 不在允许列表(未读取请求体)")
		return
	}

	r := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(connReadTimeout))
		payload, err := readMessage(r)
		if errors.Is(err, ErrMessageTooLarge) {
			s.audit(cred, "-", DecisionDeny, fmt.Sprintf("消息超过 %d 字节上限", MaxMessageBytes))
			s.denyAndClose(conn, "-", "消息超过长度上限")
			return
		}
		if errors.Is(err, ErrMalformedMessage) {
			s.audit(cred, "-", DecisionDeny, "消息帧格式非法")
			s.denyAndClose(conn, "-", "消息帧格式非法")
			return
		}
		if err != nil {
			return // io.EOF(对端关闭) / 超时回收 / 读错误
		}

		var req Request
		if err := json.Unmarshal(payload, &req); err != nil {
			s.audit(cred, "-", DecisionDeny, "JSON 解析失败")
			s.denyAndClose(conn, "-", "消息格式非法")
			return
		}
		resp, waitKey := s.decide(cred, &req)
		s.audit(cred, req.RequestID, resp.Decision, resp.Reason)

		_ = conn.SetWriteDeadline(time.Now().Add(connWriteTimeout))
		if err := writeMessage(conn, &resp); err != nil {
			return
		}

		// 需人工审批: 连接停靠等待推送(一次性客户端已拿到中间响应退出,
		// 断开由写入失败自然清理; 等待的客户端在审批落定时收到终局)。
		if waitKey != "" {
			s.parkAndWait(conn, cred, waitKey, req.RequestID)
			continue
		}
	}
}

// denyAndClose 返回明确 DENY 后关闭连接; 原因不携带内部策略细节。
func (s *Server) denyAndClose(conn net.Conn, requestID, reason string) {
	_ = conn.SetWriteDeadline(time.Now().Add(connWriteTimeout))
	_ = writeMessage(conn, &Response{
		RequestID:      requestID,
		Decision:       DecisionDeny,
		Reason:         reason,
		PolicySnapshot: PolicySnapshotV1,
	})
}

// evaluate 是 v1 固定策略表(语义可扩展, 版本随 PolicySnapshotV1 标识)。
func evaluate(req *Request, authdProxy *authd.Proxy, ttl time.Duration) Response {
	resp := Response{RequestID: req.RequestID, PolicySnapshot: PolicySnapshotV1}
	if req.RequestID == "" {
		resp.Decision = DecisionDeny
		resp.Reason = "缺少 request_id"
		return resp
	}
	switch req.ActionType {
	case ActionRequestCredential:
		if authdProxy == nil {
			resp.Decision = DecisionDeny
			resp.Reason = "凭证服务未启用"
			return resp
		}
		token, err := authdProxy.IssueSurrogate(req.Target, ttl)
		if err != nil {
			resp.Decision = DecisionDeny
			resp.Reason = "凭证不存在或不可用"
			return resp
		}
		resp.Decision = DecisionAllow
		resp.Reason = "替身令牌已签发"
		resp.SurrogateToken = token
		return resp
	case ActionCreateConnector:
		resp.Decision = DecisionRequireUserApproval
		resp.Reason = "连接器创建需用户在审批通道确认后重新提案"
		return resp
	case ActionInvokeSkill:
		if req.Scope == "read" || req.Scope == "readonly" {
			resp.Decision = DecisionAllow
			resp.Reason = "只读技能调用默认放行"
			return resp
		}
		resp.Decision = DecisionRequireUserApproval
		resp.Reason = "非只读范围需人工确认"
		return resp
	default:
		resp.Decision = DecisionDeny
		resp.Reason = "未知动作类型"
		return resp
	}
}

// decide 在固定策略表之上叠加审批闭环:
//  1. 先查决策记忆(用户已批准/已拒绝的提案直接回最终裁决);
//  2. 走 v1 固定策略表;
//  3. 结果为需人工审批时, 在审批通道落一张卡(同 key 去重),
//     并在 reason 里回执审批请求 ID。
//
// 返回的第二个值非空表示"该键已进入审批流程, 连接可停靠等待终局推送"。
// 无审批管理器(单元测试/降级部署)时退化为只回话不落卡(返回空键)。
func (s *Server) decide(cred ucred, req *Request) (Response, string) {
	key := pkey(cred.Uid, string(req.ActionType), req.Target)

	s.mu.Lock()
	if d, ok := s.decisions[key]; ok {
		s.mu.Unlock()
		reason := "用户已拒绝此提案"
		if d == DecisionAllow {
			reason = "用户已批准此提案"
		}
		return Response{RequestID: req.RequestID, Decision: d, Reason: reason, PolicySnapshot: PolicySnapshotV1}, ""
	}
	pendingID, hasPending := s.pendingCards[key]
	s.mu.Unlock()

	resp := evaluate(req, s.deps.Authd, s.deps.SurrogateTTL)
	if resp.Decision != DecisionRequireUserApproval || s.deps.Approvals == nil {
		return resp, ""
	}
	if hasPending {
		resp.Reason = fmt.Sprintf("等待用户审批(已有待审请求 %s); 连接保持等待推送, 也可处理后再提案", pendingID)
		return resp, key
	}

	areq := policy.ApprovalRequest{
		RequestID:   policy.NewRequestID(uint32(cred.Pid), time.Now()),
		Kind:        policy.KindProposal,
		ActionType:  string(req.ActionType),
		Target:      req.Target,
		UID:         cred.Uid,
		Pid:         uint32(cred.Pid),
		Comm:        readComm(cred.Pid),
		Description: fmt.Sprintf("提案通道: %s %s (scope=%s, uid=%d)", req.ActionType, req.Target, req.Scope, cred.Uid),
		Timestamp:   time.Now(),
	}
	if err := s.deps.Approvals.Submit(areq); err != nil {
		resp.Reason = "需人工审批, 但审批通道暂不可用, 请稍后重新提案"
		return resp, ""
	}
	s.mu.Lock()
	s.pendingCards[key] = areq.RequestID
	s.mu.Unlock()
	resp.Reason = fmt.Sprintf("等待用户审批(审批请求 %s); 连接保持等待推送, 批准或拒绝后终局即达", areq.RequestID)
	return resp, key
}

// parkAndWait 把连接停靠在等待者表上, 直到审批落定推送终局。
// 安全上限 = 审批超时 + 30s 余量(正常路径由推送唤醒, 不靠这个兜底)。
func (s *Server) parkAndWait(conn net.Conn, cred ucred, key, reqID string) {
	w := &waiter{reqID: reqID, ch: make(chan Response, 1)}
	s.mu.Lock()
	s.waiters[key] = append(s.waiters[key], w)
	s.mu.Unlock()

	cap := s.deps.Approvals.Timeout() + 30*time.Second
	select {
	case final := <-w.ch:
		s.audit(cred, reqID, final.Decision, final.Reason)
		_ = conn.SetWriteDeadline(time.Now().Add(connWriteTimeout))
		if err := writeMessage(conn, &final); err != nil {
			s.unregisterWaiter(key, w)
		}
	case <-time.After(cap):
		s.unregisterWaiter(key, w)
	}
}

// unregisterWaiter 把等待者移出等待表(连接已断/等待超限)。
func (s *Server) unregisterWaiter(key string, w *waiter) {
	s.mu.Lock()
	list := s.waiters[key]
	for i, x := range list {
		if x == w {
			s.waiters[key] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(s.waiters[key]) == 0 {
		delete(s.waiters, key)
	}
	s.mu.Unlock()
}

// HandleApprovalResult 消费审批结果(由守护进程结果循环按 Kind 路由进来)。
// 语义与出口管控对称: 批准→记忆 ALLOW; 拒绝→记忆 DENY;
// 超时→非裁决(仅清待审索引, 重新提案将再次等待审批)。
// 裁决落定的同时, 向所有停靠中的连接推送终局 Response。
func (s *Server) HandleApprovalResult(res approval.Result) {
	req := res.Request
	if req.Kind != policy.KindProposal {
		return
	}
	key := pkey(req.UID, req.ActionType, req.Target)

	s.mu.Lock()
	delete(s.pendingCards, key)
	if !res.TimedOut {
		d := DecisionDeny
		if res.Approved {
			d = DecisionAllow
		}
		s.decisions[key] = d
	}
	ws := s.waiters[key]
	delete(s.waiters, key)
	s.mu.Unlock()

	// 推送终局到每个等待者(缓冲 1, 永不阻塞裁决路径)
	for _, w := range ws {
		resp := Response{RequestID: w.reqID, PolicySnapshot: PolicySnapshotV1}
		switch {
		case res.TimedOut:
			resp.Decision = DecisionRequireUserApproval
			resp.Reason = "审批超时(非裁决); 重新提案可再次等待审批"
		case res.Approved:
			resp.Decision = DecisionAllow
			resp.Reason = "用户已批准此提案"
		default:
			resp.Decision = DecisionDeny
			resp.Reason = "用户已拒绝此提案"
		}
		select {
		case w.ch <- resp:
		default:
		}
	}

	if s.deps.Logger == nil {
		return
	}
	switch {
	case res.TimedOut:
		s.deps.Logger(fmt.Sprintf("[proposal] 提案审批超时(非裁决): %s %s; 重新提案将再次等待审批",
			req.ActionType, req.Target))
	case res.Approved:
		s.deps.Logger(fmt.Sprintf("[proposal] 用户批准提案: %s %s; 终局已推送等待中的 Agent",
			req.ActionType, req.Target))
	default:
		s.deps.Logger(fmt.Sprintf("[proposal] 用户拒绝提案: %s %s; 终局已推送等待中的 Agent",
			req.ActionType, req.Target))
	}
}

// readComm 读宿主 PID 的进程名(尽力而为; mgmt 以 pid:host 运行, 可直接读)。
func readComm(hostPID int32) string {
	if hostPID <= 0 {
		return ""
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", hostPID)); err == nil {
		if c := strings.TrimSpace(string(b)); c != "" {
			return c
		}
	}
	return fmt.Sprintf("agent(%d)", hostPID)
}

// audit 记录审计日志: 完整裁决链路, 不含凭证/替身令牌明文。
// PID 同时记录宿主值与(若可得)容器内值, 便于跨 PID 命名空间排查。
func (s *Server) audit(cred ucred, reqID string, d Decision, reason string) {
	if s.deps.Logger == nil {
		return
	}
	s.deps.Logger(fmt.Sprintf(
		"[proposal] 审计: req=%s uid=%d gid=%d pid=%d(容器内:%s) decision=%s reason=%s policy=%s",
		reqID, cred.Uid, cred.Gid, cred.Pid, containerPID(cred.Pid), d, reason, PolicySnapshotV1))
}

// containerPID 尽力把宿主 PID 换算成容器内 PID(读 /proc/<pid>/status
// 的 NSpid 行, 取最后一个值 = 最内层命名空间视角)。取不到返回 "<不可得>"。
func containerPID(hostPID int32) string {
	if hostPID <= 0 {
		return "<不可得>"
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", hostPID))
	if err != nil {
		return "<不可得>"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
		if len(fields) == 0 {
			break
		}
		if _, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
			return fields[len(fields)-1]
		}
		break
	}
	return "<不可得>"
}
