//go:build linux

// loader_linux.go 是加载器在 Linux 上的完整实现（目标内核 >= 5.15）：
//   - 使用 BPF ring buffer（非 perf array）接收内核事件
//   - map 不 pin: 生命周期与进程一致, 无 bpffs 运行前提
//     (内核侧调试: bpftool map dump name sentinel_allow_map)
//   - cgroup/connect4/6 通过 link.AttachCgroup 挂载（bpf_link）

package loader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/sentinel-sec/sentinel/internal/events"
)

// legacyPerfFd 记录旧通道(perf_event_open + IOC_SET_BPF)挂载的 perf 事件 fd。
type legacyPerfFd struct {
	fd    int
	event string
}

// Loader 管理 eBPF 程序和 maps。
type Loader struct {
	mu             sync.Mutex
	cfg            Config
	coll           *ebpf.Collection
	links          []link.Link   // tracepoint 链接(bpf_link 通道)
	legacyPerfFds  []legacyPerfFd // tracepoint 挂载(旧通道, bpf_link 被拒时降级)
	cgroupLinks    []link.Link   // cgroup connect 链接（可运行时重挂）
	governed       string        // 当前治理的 cgroup 路径（attach 成功后非空）
	reader         *ringbuf.Reader
	loaded         bool
	logger         func(string)
}

// New 创建加载器实例。
func New(cfg Config, logger func(string)) *Loader {
	if logger == nil {
		logger = func(string) {}
	}
	return &Loader{cfg: cfg, logger: logger}
}

// Load 从嵌入字节码加载 BPF collection 并 attach 所有程序。
func (l *Loader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loaded {
		return fmt.Errorf("eBPF 程序已加载")
	}

	// 1. 现代内核（>=5.11）以 memcg 计账，无需调整 memlock；
	//    旧环境失败仅告警，不阻断。
	if err := rlimit.RemoveMemlock(); err != nil {
		l.logger(fmt.Sprintf("[loader] 提示: memlock 调整跳过: %v", err))
	}

	// 2. 从嵌入字节码解析 collection spec
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(sentinelBPFObj))
	if err != nil {
		return fmt.Errorf("解析嵌入 BPF 字节码失败(二进制与字节码不匹配? 重新 make build): %w", err)
	}

	// 3. 加载 collection（map 不 pin: 生命周期与进程一致,
	//    内核侧调试用 bpftool map ... name <map名> 即可）
	coll, err := ebpf.NewCollection(spec)
	if err != nil && l.cfg.EnableTaintTracking {
		// fexit/kernel_clone 兜底程序需要内核 BTF 解析符号; 在无 BTF 的
		// 内核上会导致整个 collection 拒载。删除该程序重试一次, 使 BTF
		// 保持可选(此时仅失去 fork 传播的兜底通道, 主链路不受影响)。
		delete(spec.Programs, "sentinel_taint_fork_clone")
		coll, err = ebpf.NewCollection(spec)
		if err == nil {
			l.logger("[loader] 提示: 内核无 BTF, 已剔除 fexit/kernel_clone 兜底程序后加载")
		}
	}
	if err != nil {
		return fmt.Errorf("加载 BPF collection 失败(需要 root/CAP_BPF, 内核 >= 5.15): %w", err)
	}
	l.coll = coll
	l.logger(fmt.Sprintf("[loader] collection 已加载: programs=%d maps=%d",
		len(coll.Programs), len(coll.Maps)))

	// 4. attach tracepoint（污点追踪）
	if l.cfg.EnableTaintTracking {
		l.attachTracepoints(coll)
	}

	// 5. cgroup connect 钩子不做启动挂载：治理目标由 sentinel-cli
	//    cgroup <path> 运行时指定（AttachCgroup），支持"管理面与被治理
	//    容器分离"的拓扑与运行期切换目标。
	l.logger("[loader] cgroup 钩子待挂载: 用 sentinel-cli cgroup <path> 指定被治理容器")

	// 6. ring buffer reader
	eventsMap, ok := coll.Maps["events"]
	if !ok {
		return fmt.Errorf("BPF 字节码缺少 events ringbuf map")
	}
	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("创建 ringbuf reader 失败: %w", err)
	}
	l.reader = reader
	l.logger("[loader] ringbuf reader 已创建")

	l.loaded = true
	l.logger("[loader] eBPF 程序加载完成")
	return nil
}

// attachTracepoints attach 污点追踪相关的 tracepoint 程序。
func (l *Loader) attachTracepoints(coll *ebpf.Collection) {
	if err := verifySysEnterOpenatLayout(); err != nil {
		l.logger(fmt.Sprintf("[loader] 污点特性已停用: 运行内核的 sys_enter_openat 布局校验失败: %v", err))
		l.logger("[loader] 提示: 布局错位会导致 probe_read_user_str 静默失败, 故显式停用而非带病运行")
		return
	}

	tracepointProgs := []struct {
		progName string
		category string
		event    string
	}{
		{"sentinel_taint_fork", "sched", "sched_process_fork"},
		{"sentinel_taint_openat", "syscalls", "sys_enter_openat"},
		{"sentinel_cleanup_exit", "sched", "sched_process_exit"},
	}

	for _, tp := range tracepointProgs {
		prog, ok := coll.Programs[tp.progName]
		if !ok {
			l.logger(fmt.Sprintf("[loader] 未找到程序: %s", tp.progName))
			continue
		}
		lk, err := link.Tracepoint(tp.category, tp.event, prog, nil)
		if err != nil {
			// 降级: bpf_link 通道被拒(如 6.18-microsoft-standard-WSL2 对
			// sched_process_fork 返回 EACCES)时, 退回 perf_event_open +
			// IOC_SET_BPF 旧通道, 功能等价。
			fd, lerr := l.attachTracepointLegacy(tp.category, tp.event, prog)
			if lerr != nil {
				// 三级兜底(仅 fork): fexit/kernel_clone, 走 BPF trampoline,
				// 与 perf 子系统无关, 见 BPF 源码注释。
				if tp.event == "sched_process_fork" {
					if p, ok := coll.Programs["sentinel_taint_fork_clone"]; ok {
						if lk2, err2 := link.AttachTracing(link.TracingOptions{Program: p}); err2 == nil {
							l.links = append(l.links, lk2)
							l.logger(fmt.Sprintf(
								"[loader] tracepoint %s/%s 两条 perf 通道均被拒(%v), 已改用 fexit/kernel_clone 传播兜底",
								tp.category, tp.event, err))
							continue
						} else {
							l.logger(fmt.Sprintf("[loader] fexit/kernel_clone 兜底失败: %v", err2))
						}
					}
				}
				l.logger(fmt.Sprintf("[loader] attach tracepoint 失败: %s/%s: %v (旧通道也失败: %v)",
					tp.category, tp.event, err, lerr))
				continue
			}
			l.legacyPerfFds = append(l.legacyPerfFds, legacyPerfFd{fd: fd, event: tp.event})
			l.logger(fmt.Sprintf("[loader] tracepoint 已 attach(旧通道): %s/%s", tp.category, tp.event))
			continue
		}
		l.links = append(l.links, lk)
		l.logger(fmt.Sprintf("[loader] tracepoint 已 attach: %s/%s", tp.category, tp.event))
	}
}

// tracefsPathCandidates 是 tracefs 常见挂载点(与 cilium/ebpf 的查找顺序一致)。
var tracefsPathCandidates = []string{
	"/sys/kernel/tracing",
	"/sys/kernel/debug/tracing",
}

// fieldOffsetRe 匹配 tracefs format 行: "field:<type> <name>;<空格>offset:<n>;"
var fieldOffsetRe = regexp.MustCompile(`field:[^;]*[ \t](\w+);[^\n]*?offset:(\d+)`)

// parseTraceFieldOffset 从 format 内容中提取指定字段的 offset。
// 找不到返回 -1。
func parseTraceFieldOffset(format []byte, name string) int {
	for _, m := range fieldOffsetRe.FindAllSubmatch(format, -1) {
		if string(m[1]) == name {
			n := 0
			for _, c := range m[2] {
				n = n*10 + int(c-'0')
			}
			return n
		}
	}
	return -1
}

// verifySysEnterOpenatLayout 校验运行内核的 sys_enter_openat tracepoint
// 布局与 BPF 结构体假设一致(LP64: filename@24, flags@32)。
//
// 动机: ctx 偏移错位会把 dfd 当指针读, bpf_probe_read_user_str 对每次
// openat 静默 EFAULT, 污点标记链整体失效且无任何报错——该坑曾在
// Docker Desktop(WSL2) 内核上潜伏, 直到对照 format 文件才定位。
// 支持矩阵: LP64 架构(x86-64/arm64, long=8); 32 位内核布局不同, 会在此显式拒绝。
func verifySysEnterOpenatLayout() error {
	var format []byte
	var lastErr error
	for _, dir := range tracefsPathCandidates {
		b, err := os.ReadFile(filepath.Join(dir, "events/syscalls/sys_enter_openat/format"))
		if err == nil {
			format = b
			break
		}
		lastErr = err
	}
	if format == nil {
		return fmt.Errorf("无法读取 tracefs format(需挂载 tracefs): %w", lastErr)
	}

	for name, want := range map[string]int{"filename": 24, "flags": 32} {
		got := parseTraceFieldOffset(format, name)
		if got < 0 {
			return fmt.Errorf("format 中未找到字段 %s", name)
		}
		if got != want {
			return fmt.Errorf("字段 %s 位于 offset %d, 与 LP64 预期 %d 不符(非 LP64 内核?)", name, got, want)
		}
	}
	return nil
}

// readTracepointID 从 tracefs 读取 tracepoint 的事件 ID。
func readTracepointID(system, name string) (uint32, error) {
	for _, dir := range tracefsPathCandidates {
		b, err := os.ReadFile(filepath.Join(dir, "events", system, name, "id"))
		if err == nil {
			id, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
			if perr != nil {
				return 0, fmt.Errorf("tracepoint %s/%s id 解析失败: %w", system, name, perr)
			}
			return uint32(id), nil
		}
	}
	return 0, fmt.Errorf("无法读取 tracepoint %s/%s 的 id(需挂载 tracefs)", system, name)
}

// attachTracepointLegacy 以旧通道挂载 tracepoint:
// perf_event_open(disabled) → PERF_EVENT_IOC_SET_BPF → PERF_EVENT_IOC_ENABLE。
// 这是 bpf_link_create(5.15+) 普及前 libbpf 的标准路径, 功能等价,
// fd 生命周期随进程。动机: 某些内核(实测 6.18-microsoft-standard-WSL2)
// 对个别 tracepoint(如 sched_process_fork)的 bpf_link_create 返回 EACCES,
// 同批其他事件正常, 旧通道不受影响。
//
// perf_event_attr 手工按 PERF_ATTR_SIZE_VER0(64B)布局打包:
// x/sys 的 PerfEventAttr 字段表示随版本漂移(v0.43.0 已与常见写法不同),
// 而 perf_event_attr 本身是极稳定的内核 UAPI, 字节布局直写更可靠。
func (l *Loader) attachTracepointLegacy(system, name string, prog *ebpf.Program) (int, error) {
	id, err := readTracepointID(system, name)
	if err != nil {
		return -1, err
	}

	var attr [64]byte
	binary.LittleEndian.PutUint32(attr[0:4], 2)           /* type = PERF_TYPE_TRACEPOINT */
	binary.LittleEndian.PutUint32(attr[4:8], 64)          /* size = PERF_ATTR_SIZE_VER0 */
	binary.LittleEndian.PutUint64(attr[8:16], uint64(id)) /* config = tracepoint id */
	binary.LittleEndian.PutUint64(attr[16:24], 1)         /* sample_period = 1 */
	/* attr[24:32] sample_type = 0; attr[32:40] read_format = 0 */
	binary.LittleEndian.PutUint64(attr[40:48], 1)         /* 位标志字: bit0 = disabled */

	fd, _, errno := unix.Syscall6(unix.SYS_PERF_EVENT_OPEN,
		uintptr(unsafe.Pointer(&attr[0])), // attr
		^uintptr(0),                       // pid = -1
		0,                                 // cpu = 0
		^uintptr(0),                       // group_fd = -1
		unix.PERF_FLAG_FD_CLOEXEC,
		0)
	if errno != 0 {
		return -1, fmt.Errorf("perf_event_open: %w", errno)
	}
	if err := unix.IoctlSetInt(int(fd), unix.PERF_EVENT_IOC_SET_BPF, int(prog.FD())); err != nil {
		unix.Close(int(fd))
		return -1, fmt.Errorf("IOC_SET_BPF: %w", err)
	}
	if err := unix.IoctlSetInt(int(fd), unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(int(fd))
		return -1, fmt.Errorf("IOC_ENABLE: %w", err)
	}
	return int(fd), nil
}

// attachCgroupHooks attach cgroup sockaddr 程序到指定 cgroup（调用方持锁）。
// 挂载成功后把该路径记为治理目标。
func (l *Loader) attachCgroupHooks(path string) {
	cgroupProgs := []struct {
		progName string
		attach   ebpf.AttachType
		enabled  bool
	}{
		{"sentinel_connect4", ebpf.AttachCGroupInet4Connect, l.cfg.EnableConnect4},
		{"sentinel_connect6", ebpf.AttachCGroupInet6Connect, l.cfg.EnableConnect6},
	}

	attached := 0
	for _, cg := range cgroupProgs {
		if !cg.enabled {
			continue
		}
		prog, ok := l.coll.Programs[cg.progName]
		if !ok {
			l.logger(fmt.Sprintf("[loader] 未找到程序: %s", cg.progName))
			continue
		}
		lk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  cg.attach,
			Program: prog,
		})
		if err != nil {
			l.logger(fmt.Sprintf("[loader] attach cgroup 失败: %s → %s: %v", cg.progName, path, err))
			continue
		}
		l.cgroupLinks = append(l.cgroupLinks, lk)
		attached++
		l.logger(fmt.Sprintf("[loader] cgroup hook 已 attach: %s → %s", cg.progName, path))
	}
	if attached > 0 {
		l.governed = path
	}
}

// AttachCgroup 运行时挂载 cgroup connect 钩子并设为治理目标
// （sentinel-cli cgroup <path> 命令的后端）。
// 重复调用会先卸载旧钩子再挂载新目标。
func (l *Loader) AttachCgroup(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded || l.coll == nil {
		return fmt.Errorf("eBPF 程序未加载")
	}
	if path == "" {
		return fmt.Errorf("cgroup 路径为空")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("cgroup 路径必须是绝对路径: %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cgroup 目录不存在(需 cgroupns=host 才能看见兄弟容器): %s: %w", path, err)
	}

	l.closeCgroupLinksLocked()
	l.attachCgroupHooks(path)
	if l.governed != path {
		return fmt.Errorf("cgroup 钩子挂载失败(详见守护进程日志)")
	}
	return nil
}

// GovernedCgroup 返回当前治理的 cgroup 路径（未挂载为空串）。
func (l *Loader) GovernedCgroup() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.governed
}

// closeCgroupLinksLocked 卸载全部 cgroup 钩子并清空治理目标（调用方持锁）。
func (l *Loader) closeCgroupLinksLocked() {
	for i, lk := range l.cgroupLinks {
		if err := lk.Close(); err != nil {
			l.logger(fmt.Sprintf("[loader] detach cgroup link %d 失败: %v", i, err))
		}
	}
	l.cgroupLinks = nil
	l.governed = ""
}

// ReadEvents 从 ring buffer 读取事件并分发到处理器，直到 reader 关闭。
// Close() 会触发返回。此方法阻塞，应在独立 goroutine 中运行。
func (l *Loader) ReadEvents(handler EventHandler) error {
	l.mu.Lock()
	reader := l.reader
	l.mu.Unlock()

	if reader == nil {
		return fmt.Errorf("ringbuf reader 未初始化")
	}

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("读取 ringbuf 事件失败: %w", err)
		}

		if len(record.RawSample) < 4 {
			continue
		}
		evtType := uint32(record.RawSample[0]) | uint32(record.RawSample[1])<<8 |
			uint32(record.RawSample[2])<<16 | uint32(record.RawSample[3])<<24

		handler(events.EventDesc{
			Raw:  record.RawSample,
			Type: evtType,
		})
	}
}

// mapFor 返回指定名称的 map（调用方需持有锁）。
func (l *Loader) mapFor(name string) (*ebpf.Map, error) {
	if !l.loaded || l.coll == nil {
		return nil, fmt.Errorf("eBPF 程序未加载")
	}
	m, ok := l.coll.Maps[name]
	if !ok {
		return nil, fmt.Errorf("map 不存在: %s", name)
	}
	return m, nil
}

// SetAllow 实现 policy.MapSync：更新内核允许列表 map。
func (l *Loader) SetAllow(key events.NetKey, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, err := l.mapFor("allow_map")
	if err != nil {
		return err
	}
	return l.updateAllowMap(m, key, on)
}

// SetDeny 实现 policy.MapSync：更新内核拒绝列表 map。
func (l *Loader) SetDeny(key events.NetKey, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, err := l.mapFor("deny_map")
	if err != nil {
		return err
	}
	return l.updateAllowMap(m, key, on)
}

// SetTempAllow 实现 policy.MapSync：更新内核临时放行 map。
func (l *Loader) SetTempAllow(key events.NetKey, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, err := l.mapFor("temp_allow_map")
	if err != nil {
		return err
	}
	return l.updateAllowMap(m, key, on)
}

func (l *Loader) updateAllowMap(m *ebpf.Map, key events.NetKey, on bool) error {
	if on {
		return m.Update(key, uint32(1), ebpf.UpdateAny)
	}
	return m.Delete(key)
}

// SetTaint 手动设置进程污点状态（CLI taint/untaint 命令后端）。
func (l *Loader) SetTaint(pid uint32, dirty bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, err := l.mapFor("taint_map")
	if err != nil {
		return err
	}
	if dirty {
		return m.Update(pid, uint32(1), ebpf.UpdateAny)
	}
	return m.Delete(pid)
}

// SetWatchPath 把受监控路径前缀写入 watch_map 的指定下标。
// 内核侧 MAX_WATCH_PATHS=8、单条前缀 <= 63 字节。
func (l *Loader) SetWatchPath(idx int, prefix string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, err := l.mapFor("watch_map")
	if err != nil {
		return err
	}
	if idx < 0 {
		return fmt.Errorf("下标无效: %d", idx)
	}
	var wp events.WatchPath
	n := copy(wp.Prefix[:], prefix)
	wp.Len = uint32(n)
	return m.Update(uint32(idx), wp, ebpf.UpdateAny)
}

// Close 卸载所有 eBPF 程序并清理资源。
func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return nil
	}
	l.logger("[loader] 开始卸载 eBPF 程序...")

	// 先关 reader（解除 ReadEvents 阻塞）
	if l.reader != nil {
		l.reader.Close()
		l.reader = nil
	}
	for i, lk := range l.links {
		if err := lk.Close(); err != nil {
			l.logger(fmt.Sprintf("[loader] detach link %d 失败: %v", i, err))
		}
	}
	l.links = nil
	for _, pf := range l.legacyPerfFds {
		if err := unix.Close(pf.fd); err != nil {
			l.logger(fmt.Sprintf("[loader] 关闭旧通道挂载 %s 失败: %v", pf.event, err))
		}
	}
	l.legacyPerfFds = nil
	l.closeCgroupLinksLocked()
	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
	}

	l.loaded = false
	l.logger("[loader] eBPF 程序已卸载")
	return nil
}

// IsLoaded 返回是否已加载。
func (l *Loader) IsLoaded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loaded
}

// Stats 返回加载器运行状态摘要。
func (l *Loader) Stats() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded || l.coll == nil {
		return "未加载"
	}
	gov := ""
	if l.governed != "" {
		gov = " governed=" + l.governed
	}
	return fmt.Sprintf("已加载 | maps=%d programs=%d links=%d%s",
		len(l.coll.Maps), len(l.coll.Programs), len(l.links)+len(l.cgroupLinks), gov)
}
