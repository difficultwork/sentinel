// Package loader 负责加载 eBPF 程序和 maps，并管理它们的生命周期。
//
// 字节码在构建期通过 go:embed 编译进 Go 二进制：clang 把
// bpf/sentinel.bpf.c 直接编译到本包目录的 sentinel.bpf.o（与加载器
// 同目录，无拷贝步骤，见 Makefile）。运行时不读取任何 .o 文件——
// 部署只需单个可执行文件。
//
// 目标内核 >= 5.15：
//   - 使用 BPF ring buffer（非 perf array）接收内核事件
//   - map 通过 LIBBPF_PIN_BY_NAME + MapOptions.PinPath 自动 pin
//   - cgroup/connect4/6 通过 link.AttachCgroup 挂载（bpf_link）
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/sentinel-sec/sentinel/internal/events"
)

// BPF 字节码在构建期嵌入。Makefile 用 clang 把 bpf/sentinel.bpf.c
// 直接编译生成本文件（编译产物，勿手工提交或编辑）。
//
//go:embed sentinel.bpf.o
var sentinelBPFObj []byte

// Config 是加载器的配置。
type Config struct {
	PinPath    string // BPF map pin 目录（默认 /sys/fs/bpf/sentinel）
	CgroupPath string // cgroup attach 根路径（默认 /sys/fs/cgroup）

	EnableConnect4      bool
	EnableConnect6      bool
	EnableTaintTracking bool
}

// Loader 管理 eBPF 程序和 maps。
type Loader struct {
	mu     sync.Mutex
	cfg    Config
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
	loaded bool
	logger func(string)
}

// New 创建加载器实例。
func New(cfg Config, logger func(string)) *Loader {
	if logger == nil {
		logger = func(string) {}
	}
	if cfg.PinPath == "" {
		cfg.PinPath = "/sys/fs/bpf/sentinel"
	}
	if cfg.CgroupPath == "" {
		cfg.CgroupPath = "/sys/fs/cgroup"
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

	// 2. 清理旧 pin 目录，保证本次加载状态确定
	if err := os.RemoveAll(l.cfg.PinPath); err != nil {
		l.logger(fmt.Sprintf("[loader] 警告: 清理旧 pin 目录失败: %s: %v", l.cfg.PinPath, err))
	}
	if err := os.MkdirAll(l.cfg.PinPath, 0755); err != nil {
		return fmt.Errorf("创建 pin 目录失败 %s: %w", l.cfg.PinPath, err)
	}

	// 3. 从嵌入字节码解析 collection spec
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(sentinelBPFObj))
	if err != nil {
		return fmt.Errorf("解析嵌入 BPF 字节码失败（二进制与字节码不匹配？重新 make build）: %w", err)
	}

	// 4. 加载 collection；带 pin 选项的 map 自动按名 pin
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: l.cfg.PinPath},
	})
	if err != nil {
		return fmt.Errorf("加载 BPF collection 失败（需要 root/CAP_BPF，内核 >= 5.15）: %w", err)
	}
	l.coll = coll
	l.logger(fmt.Sprintf("[loader] collection 已加载: programs=%d maps=%d",
		len(coll.Programs), len(coll.Maps)))

	// 5. attach tracepoint（污点追踪）
	if l.cfg.EnableTaintTracking {
		l.attachTracepoints(coll)
	}

	// 6. attach cgroup connect 钩子
	if l.cfg.EnableConnect4 || l.cfg.EnableConnect6 {
		l.attachCgroupHooks(coll)
	}

	// 7. ring buffer reader
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
			l.logger(fmt.Sprintf("[loader] attach tracepoint 失败: %s/%s: %v", tp.category, tp.event, err))
			continue
		}
		l.links = append(l.links, lk)
		l.logger(fmt.Sprintf("[loader] tracepoint 已 attach: %s/%s", tp.category, tp.event))
	}
}

// attachCgroupHooks attach cgroup sockaddr 程序。
func (l *Loader) attachCgroupHooks(coll *ebpf.Collection) {
	cgroupProgs := []struct {
		progName string
		attach   ebpf.AttachType
		enabled  bool
	}{
		{"sentinel_connect4", ebpf.AttachCGroupInet4Connect, l.cfg.EnableConnect4},
		{"sentinel_connect6", ebpf.AttachCGroupInet6Connect, l.cfg.EnableConnect6},
	}

	for _, cg := range cgroupProgs {
		if !cg.enabled {
			continue
		}
		prog, ok := coll.Programs[cg.progName]
		if !ok {
			l.logger(fmt.Sprintf("[loader] 未找到程序: %s", cg.progName))
			continue
		}
		lk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    l.cfg.CgroupPath,
			Attach:  cg.attach,
			Program: prog,
		})
		if err != nil {
			l.logger(fmt.Sprintf("[loader] attach cgroup 失败: %s → %s: %v", cg.progName, l.cfg.CgroupPath, err))
			continue
		}
		l.links = append(l.links, lk)
		l.logger(fmt.Sprintf("[loader] cgroup hook 已 attach: %s → %s", cg.progName, l.cfg.CgroupPath))
	}
}

// EventHandler 处理从 ring buffer 读取的事件。
type EventHandler func(events.EventDesc)

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
	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
	}
	// 清理 pin 文件
	if entries, err := os.ReadDir(l.cfg.PinPath); err == nil {
		for _, entry := range entries {
			_ = os.Remove(filepath.Join(l.cfg.PinPath, entry.Name()))
		}
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
	return fmt.Sprintf("已加载 | maps=%d programs=%d links=%d pin=%s",
		len(l.coll.Maps), len(l.coll.Programs), len(l.links), l.cfg.PinPath)
}
