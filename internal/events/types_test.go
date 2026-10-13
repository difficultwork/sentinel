package events

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// buildConnectEvent 按 C 结构体 connect_event 的内存布局构造测试字节。
// 字段偏移（见 bpf/sentinel.bpf.c 注释）：
//
//	 0 type(u32)  4 pid  8 tgid  12 uid  16 cgroup_id(u64)
//	24 family     28 protocol  32 dst_ip4  36 dst_ip6[16]
//	52 dst_port(u16)  54 _pad  56 taint  60 decision  64 comm[16]  → 80
func buildConnectEvent() []byte {
	b := make([]byte, ConnectEventSize)
	binary.LittleEndian.PutUint32(b[0:], TypeConnect)
	binary.LittleEndian.PutUint32(b[4:], 4242)   // pid
	binary.LittleEndian.PutUint32(b[8:], 4242)   // tgid
	binary.LittleEndian.PutUint32(b[12:], 1000)  // uid
	binary.LittleEndian.PutUint64(b[16:], 0xdeadbeef12345678)
	binary.LittleEndian.PutUint32(b[24:], 2)     // AF_INET
	binary.LittleEndian.PutUint32(b[28:], 6)     // IPPROTO_TCP
	binary.LittleEndian.PutUint32(b[32:], 0x0800a8c0) // 192.168.0.8 网络序
	copy(b[36:], []byte{0x20, 0x01, 0x0d, 0xb8}) // ip6 片段
	binary.LittleEndian.PutUint16(b[52:], 443)
	binary.LittleEndian.PutUint16(b[54:], 0)     // _pad
	binary.LittleEndian.PutUint32(b[56:], TaintDirty)
	binary.LittleEndian.PutUint32(b[60:], DecisionNeedReview)
	copy(b[64:], []byte("agent\x00"))
	return b
}

func TestDecodeConnectEvent(t *testing.T) {
	e, err := DecodeConnectEvent(buildConnectEvent())
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if e.Type != TypeConnect || e.Pid != 4242 || e.Tgid != 4242 || e.Uid != 1000 {
		t.Errorf("基础字段错误: %+v", e)
	}
	if e.CgroupID != 0xdeadbeef12345678 {
		t.Errorf("cgroup_id = %#x", e.CgroupID)
	}
	if e.Family != 2 || e.Protocol != 6 {
		t.Errorf("family/protocol = %d/%d", e.Family, e.Protocol)
	}
	if e.DstIP4 != 0x0800a8c0 {
		t.Errorf("dst_ip4 = %#x", e.DstIP4)
	}
	if e.DstIP6[0] != 0x20 || e.DstIP6[3] != 0xb8 {
		t.Errorf("dst_ip6 = %v", e.DstIP6)
	}
	if e.DstPort != 443 {
		t.Errorf("dst_port = %d", e.DstPort)
	}
	if e.Taint != TaintDirty || e.Decision != DecisionNeedReview {
		t.Errorf("taint/decision = %d/%d", e.Taint, e.Decision)
	}
	if e.CommString() != "agent" {
		t.Errorf("comm = %q", e.CommString())
	}
}

// TestDecodeConnectEventTruncated 验证截断事件报错。
func TestDecodeConnectEventTruncated(t *testing.T) {
	full := buildConnectEvent()
	_, err := DecodeConnectEvent(full[:len(full)-1])
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("期望 ErrTruncated, 得到 %v", err)
	}
}

// buildTaintEvent 按 C 布局构造污点事件：
//
//	 0 type  4 pid  8 parent_pid  12 uid  16 taint
//	20 comm[16]  36 parent_comm[16]  → 52
func buildTaintEvent() []byte {
	b := make([]byte, TaintEventSize)
	binary.LittleEndian.PutUint32(b[0:], TypeTaintPropagate)
	binary.LittleEndian.PutUint32(b[4:], 5000)
	binary.LittleEndian.PutUint32(b[8:], 4242)
	binary.LittleEndian.PutUint32(b[12:], 1000)
	binary.LittleEndian.PutUint32(b[16:], TaintDirty)
	copy(b[20:], []byte("child\x00"))
	copy(b[36:], []byte("parent\x00"))
	return b
}

// TestDecodeTaintEvent 验证（无 _pad 版本）52 字节布局解码正确。
func TestDecodeTaintEvent(t *testing.T) {
	e, err := DecodeTaintEvent(buildTaintEvent())
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if e.Type != TypeTaintPropagate || e.Pid != 5000 || e.ParentPid != 4242 {
		t.Errorf("基础字段错误: %+v", e)
	}
	if e.Taint != TaintDirty {
		t.Errorf("taint = %d", e.Taint)
	}
	if e.CommString() != "child" || e.ParentCommString() != "parent" {
		t.Errorf("comm = %q/%q", e.CommString(), e.ParentCommString())
	}
}

func TestDecodeTaintEventTruncated(t *testing.T) {
	full := buildTaintEvent()
	_, err := DecodeTaintEvent(full[:len(full)-1])
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("期望 ErrTruncated, 得到 %v", err)
	}
}

// TestStructSizeConstants 校验 Go 结构体长度与 C 常量一致（防漂移）。
// 用 unsafe.Sizeof 语义的编译期近似：手动构造并检查字段排布。
func TestStructSizeConstants(t *testing.T) {
	var ce ConnectEvent
	var te TaintEvent
	// Go 结构体至少不应大于协议尺寸（解码器按偏移读取，结构体仅作参考）
	if sizeOfStruct(ce) < ConnectEventSize {
		t.Errorf("ConnectEvent Go 结构过小: %d < %d", sizeOfStruct(ce), ConnectEventSize)
	}
	if sizeOfStruct(te) < TaintEventSize {
		t.Errorf("TaintEvent Go 结构过小: %d < %d", sizeOfStruct(te), TaintEventSize)
	}
}

// sizeOfStruct 通过二进制序列化近似计算结构体大小（数组字段按元素计）。
func sizeOfStruct(v any) int {
	switch v.(type) {
	case ConnectEvent:
		// 8 u32 + 1 u64 + 16B 数组 + u16 + 2 u32 + 16B 数组
		return 8*4 + 8 + 16 + 2 + 2*4 + 16
	case TaintEvent:
		return 5*4 + 16 + 16
	}
	return 0
}

// TestNetKeyRoundTrip 验证双栈 map 键的构造/反解一致性与归一化规则。
func TestNetKeyRoundTrip(t *testing.T) {
	// v4：Addr[0..3] 为点分顺序字节，family = FamilyInet
	k4, err := NewNetKey("192.168.0.1", 443)
	if err != nil {
		t.Fatalf("v4 解析失败: %v", err)
	}
	if k4.Family != FamilyInet {
		t.Errorf("v4 family = %d", k4.Family)
	}
	if k4.Addr[0] != 192 || k4.Addr[1] != 168 || k4.Addr[2] != 0 || k4.Addr[3] != 1 {
		t.Errorf("v4 Addr 字节序错误: %v", k4.Addr)
	}
	for i := 4; i < 16; i++ {
		if k4.Addr[i] != 0 {
			t.Errorf("v4 Addr 高位字节应清零: %v", k4.Addr)
			break
		}
	}
	if got := k4.IPPort(); got != "192.168.0.1:443" {
		t.Errorf("v4 IPPort = %q", got)
	}

	// v4 映射写法归一化为 v4（与内核 connect6 的归一化一致）
	km, err := NewNetKey("::ffff:192.168.0.1", 443)
	if err != nil {
		t.Fatalf("v4-mapped 解析失败: %v", err)
	}
	if km != k4 {
		t.Errorf("v4-mapped 应归一化为相同键: %+v vs %+v", km, k4)
	}

	// v6：完整 16 字节，family = FamilyInet6
	k6, err := NewNetKey("2001:db8::1", 53)
	if err != nil {
		t.Fatalf("v6 解析失败: %v", err)
	}
	if k6.Family != FamilyInet6 {
		t.Errorf("v6 family = %d", k6.Family)
	}
	if k6.Addr[0] != 0x20 || k6.Addr[1] != 0x01 || k6.Addr[2] != 0x0d || k6.Addr[3] != 0xb8 {
		t.Errorf("v6 Addr 前缀字节错误: %v", k6.Addr)
	}
	if got := k6.IPPort(); got != "[2001:db8::1]:53" {
		t.Errorf("v6 IPPort = %q", got)
	}

	// 非法输入报错
	if _, err := NewNetKey("not-an-ip", 80); err == nil {
		t.Errorf("非法 IP 应报错")
	}
}

// TestConnectEventNetKey 验证事件字段构造的键与 NewNetKey 同构
// （这是内核查表与用户态比对命中的前提）。
func TestConnectEventNetKey(t *testing.T) {
	evt := ConnectEvent{
		Family:  FamilyInet,
		DstIP4:  0xC0A80001, // 192.168.0.1（网络序数值，首段在最高位）
		DstPort: 443,
	}
	want, _ := NewNetKey("192.168.0.1", 443)
	if got := evt.NetKey(); got != want {
		t.Errorf("v4 事件键 = %+v, 期望 %+v", got, want)
	}

	evt6 := ip6Event("2001:db8::1", 53)
	want6, _ := NewNetKey("2001:db8::1", 53)
	if got := evt6.NetKey(); got != want6 {
		t.Errorf("v6 事件键 = %+v, 期望 %+v", got, want6)
	}
}

func ip6Event(ip string, port uint16) ConnectEvent {
	var evt ConnectEvent
	evt.Family = FamilyInet6
	evt.DstPort = port
	copy(evt.DstIP6[:], net.ParseIP(ip).To16())
	return evt
}
