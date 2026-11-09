//go:build linux

// Package proposal 实现基于 Unix 域套接字与 SO_PEERCRED 的跨容器提案通道。
//
// 定位与边界(与网络出口管控相互独立):
//   - 通道只负责"连接器动作提案"的提交与裁决;
//   - 全程 AF_UNIX, 不产生任何 TCP/UDP 收发, 因此不会触发
//     cgroup/connect4/connect6 出口钩子;
//   - 提案获批后 Agent 发起的真实网络请求, 仍由出口钩子独立审批。
//
// 安全模型:
//   - 身份唯一依据 accept() 后内核返回的 SO_PEERCRED(uid/gid/pid),
//     消息体内的任何身份字段不参与授权;
//   - 身份不符: 不读取请求体, 直接断开并审计;
//   - 套接字目录与文件权限是第二道防线, 不作为唯一判定。
package proposal

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// 帧格式: 4 字节大端长度 + JSON 载荷(一问一答, 双向同构)。
const (
	frameHeaderBytes = 4

	// MaxMessageBytes 单条消息(含头)上限; 超限直接拒绝并记录,
	// 防止异常客户端用超大消息拖垮服务端。
	MaxMessageBytes = 64 << 10

	// PolicySnapshotV1 当前裁决依据的固定策略版本标识。
	// v1 语义(见 evaluate): 建连接器→需人工审批; 申请凭证→存在即发
	// 替身令牌; 调用技能→只读放行, 其余需人工审批。
	PolicySnapshotV1 = "fixed-policy-v1"
)

// ErrMessageTooLarge 表示消息超过 MaxMessageBytes。
var ErrMessageTooLarge = errors.New("proposal: 消息超过长度上限")

// ErrMalformedMessage 表示帧头或载荷不合法。
var ErrMalformedMessage = errors.New("proposal: 消息格式非法")

// ActionType 是提案的动作类型枚举。
type ActionType string

const (
	ActionCreateConnector   ActionType = "CREATE_CONNECTOR"   // 创建连接器
	ActionRequestCredential ActionType = "REQUEST_CREDENTIAL" // 请求凭证(替身令牌)
	ActionInvokeSkill       ActionType = "INVOKE_SKILL"       // 调用已保存 skill
)

// Decision 是裁决结果枚举。
type Decision string

const (
	DecisionAllow              Decision = "ALLOW"
	DecisionDeny               Decision = "DENY"
	DecisionRequireUserApproval Decision = "REQUIRE_USER_APPROVAL"
)

// Request 是 Agent 提交的提案消息。
type Request struct {
	RequestID     string     `json:"request_id"`      // 客户端生成, 用于匹配响应
	ActionType    ActionType `json:"action_type"`     // 动作类型
	Target        string     `json:"target"`          // 目标服务标识(如 gmail / 凭证 ID)
	Scope         string     `json:"scope"`           // 权限范围: read / write / full
	ContextDigest string     `json:"context_digest"`  // 任务上下文摘要(仅供策略参考, 不写入审计)
	Timestamp     int64      `json:"timestamp"`       // 客户端时间戳(unix 秒)
}

// Response 是 Sentinel 的裁决响应。
type Response struct {
	RequestID      string   `json:"request_id"`               // 回显
	Decision       Decision `json:"decision"`                 // 裁决
	Reason         string   `json:"reason,omitempty"`         // 可读原因
	PolicySnapshot string   `json:"policy_snapshot"`          // 裁决依据的策略版本
	SurrogateToken string   `json:"surrogate_token,omitempty"` // 仅 ALLOW 且涉及凭证时
}

// writeMessage 编码并写入一条帧消息。
func writeMessage(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proposal: JSON 编码失败: %w", err)
	}
	if len(payload) > MaxMessageBytes {
		return ErrMessageTooLarge
	}
	frame := make([]byte, frameHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(frame[:frameHeaderBytes], uint32(len(payload)))
	copy(frame[frameHeaderBytes:], payload)
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("proposal: 写入失败: %w", err)
	}
	return nil
}

// readMessage 读取一条帧消息, 返回 JSON 载荷。
// 长度超限返回 ErrMessageTooLarge(不消费载荷), 帧头异常返回 ErrMalformedMessage。
func readMessage(r io.Reader) ([]byte, error) {
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err // 含 io.EOF: 对端正常关闭
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 {
		return nil, ErrMalformedMessage
	}
	if n > MaxMessageBytes {
		return nil, ErrMessageTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("proposal: 载荷读取失败: %w", err)
	}
	return payload, nil
}
