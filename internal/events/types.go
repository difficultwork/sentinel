// Package events 定义 Sentinel eBPF 内核态与用户态之间的共享数据结构与解码器。
//
// 这些结构必须与 bpf/sentinel.bpf.c 中的 C 定义保持内存布局一致。
// 解码采用逐字段 binary.LittleEndian 读取（x86_64/arm64 均为小端主机序，
// ringbuf 中的数据按内核本机字节序写入），不依赖 unsafe，不受 Go 编译器
// 字段对齐差异影响。
package events

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// 事件类型枚举，与 sentinel.bpf.c 中的 enum sentinel_event_type 对应。
const (
	TypeConnect        = 1 // 进程发起网络连接（含内核侧初步决策）
	TypeTaintMarked    = 2 // 进程被标记为已污染
	TypeTaintPropagate = 3 // 污点通过 fork 传播
)

// 决策类型枚举，与 enum sentinel_decision 对应。
const (
	DecisionAllow      = 0 // 自动放行
	DecisionDeny       = 1 // 立即阻断
	DecisionNeedReview = 2 // 需要人工审批
)

// 污点状态枚举，与 enum taint_state 对应。
const (
	TaintClean = 0
	TaintDirty = 1
)

// 结构体大小常量，与 C 侧 sizeof 保持一致。
const (
	ConnectEventSize = 80
	TaintEventSize   = 52
	AllowKeySize     = 8
)

// ConnectEvent 对应 C 结构体 connect_event（80 字节）。
// 字段顺序与大小必须与内核态一致。
type ConnectEvent struct {
	Type     uint32   // EVENT_CONNECT
	Pid      uint32   // 发起连接的进程 tgid
	Tgid     uint32   // 线程组 ID（与 Pid 相同，保留以对齐 C 布局）
	Uid      uint32   // 用户 ID
	CgroupID uint64   // 64 位 cgroup v2 ID
	Family   uint32   // AF_INET / AF_INET6
	Protocol uint32   // IP 协议号
	DstIP4   uint32   // 目标 IPv4（网络字节序）
	DstIP6   [16]byte // 目标 IPv6（原始字节）
	DstPort  uint16   // 目标端口（主机字节序）
	Taint    uint32   // 发起连接时的污点状态
	Decision uint32   // 内核侧决策
	Comm     [16]byte // 进程名
}

// TaintEvent 对应 C 结构体 taint_event（52 字节，无隐式填充）。
type TaintEvent struct {
	Type       uint32   // EVENT_TAINT_MARKED / EVENT_TAINT_PROPAGATE
	Pid        uint32   // 被污染的进程 tgid（或 fork 出的子进程）
	ParentPid  uint32   // 父进程 tgid（传播事件）
	Uid        uint32   // 用户 ID
	Taint      uint32   // TAINT_DIRTY
	Comm       [16]byte // 进程名
	ParentComm [16]byte // 父进程名
}

// AllowKey 对应 C 结构体 allow_key，用于 BPF map 查询/更新。
type AllowKey struct {
	IP4  uint32 // 网络字节序
	Port uint16 // 主机字节序
	_pad uint16
}

// WatchPath 对应 C 结构体 watch_path，写入 watch_map（ARRAY）。
type WatchPath struct {
	Prefix [64]byte
	Len    uint32
}

// EventDesc 是从 ring buffer 读取到的事件的统一包装。
type EventDesc struct {
	Raw  []byte // 原始字节
	Type uint32 // 事件类型（从 Raw 前 4 字节读取）
}

// ErrTruncated 表示事件字节数不足以完成解码。
var ErrTruncated = errors.New("sentinel/events: event payload truncated")

// DecodeConnectEvent 从 ringbuf 原始字节解码 ConnectEvent。
// 按字段顺序显式读取，跳过 C 侧的显式填充字节，保证两端布局解耦。
func DecodeConnectEvent(b []byte) (ConnectEvent, error) {
	var e ConnectEvent
	if len(b) < ConnectEventSize {
		return e, fmt.Errorf("%w: connect event need %d bytes, got %d",
			ErrTruncated, ConnectEventSize, len(b))
	}
	r := binaryReader{b: b}
	e.Type = r.u32()
	e.Pid = r.u32()
	e.Tgid = r.u32()
	e.Uid = r.u32()
	e.CgroupID = r.u64()
	e.Family = r.u32()
	e.Protocol = r.u32()
	e.DstIP4 = r.u32()
	r.bytes(e.DstIP6[:])
	e.DstPort = r.u16()
	r.skip(2) // C 侧 _pad
	e.Taint = r.u32()
	e.Decision = r.u32()
	r.bytes(e.Comm[:])
	return e, nil
}

// DecodeTaintEvent 从 ringbuf 原始字节解码 TaintEvent。
func DecodeTaintEvent(b []byte) (TaintEvent, error) {
	var e TaintEvent
	if len(b) < TaintEventSize {
		return e, fmt.Errorf("%w: taint event need %d bytes, got %d",
			ErrTruncated, TaintEventSize, len(b))
	}
	r := binaryReader{b: b}
	e.Type = r.u32()
	e.Pid = r.u32()
	e.ParentPid = r.u32()
	e.Uid = r.u32()
	e.Taint = r.u32()
	r.bytes(e.Comm[:])
	r.bytes(e.ParentComm[:])
	return e, nil
}

// binaryReader 是小端序顺序读取器。
type binaryReader struct {
	b []byte
	o int
}

func (r *binaryReader) u16() uint16 {
	v := binary.LittleEndian.Uint16(r.b[r.o:])
	r.o += 2
	return v
}

func (r *binaryReader) u32() uint32 {
	v := binary.LittleEndian.Uint32(r.b[r.o:])
	r.o += 4
	return v
}

func (r *binaryReader) u64() uint64 {
	v := binary.LittleEndian.Uint64(r.b[r.o:])
	r.o += 8
	return v
}

func (r *binaryReader) bytes(dst []byte) {
	copy(dst, r.b[r.o:r.o+len(dst)])
	r.o += len(dst)
}

func (r *binaryReader) skip(n int) {
	r.o += n
}

// CommString 返回 ConnectEvent.Comm 的字符串形式（去除 NUL 尾部）。
func (e ConnectEvent) CommString() string { return cstr(e.Comm[:]) }

// CommString 返回 TaintEvent.Comm 的字符串形式。
func (e TaintEvent) CommString() string { return cstr(e.Comm[:]) }

// ParentCommString 返回 TaintEvent.ParentComm 的字符串形式。
func (e TaintEvent) ParentCommString() string { return cstr(e.ParentComm[:]) }

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
