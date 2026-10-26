//go:build !linux

// loader_other.go 是加载器在非 Linux 平台（Windows/macOS 等）上的桩实现。
// eBPF 是 Linux 内核特性，这些平台上：
//   - 编译完全通过（cilium/ebpf 仅在 loader_linux.go 中被引用）
//   - --dry-run 模拟模式完全可用（策略引擎/审批通道/凭证代理均为纯用户态）
//   - 完整模式下所有 eBPF 相关调用返回 ErrUnsupportedPlatform
package loader

import (
	"fmt"
	"runtime"

	"github.com/sentinel-sec/sentinel/internal/events"
)

// Loader 在非 Linux 平台上是同构的桩：结构体只保留配置与日志，
// 不引用任何平台相关类型。
type Loader struct {
	cfg    Config
	logger func(string)
}

// New 创建加载器实例（非 Linux 平台同样可用，Load 时才报受限）。
func New(cfg Config, logger func(string)) *Loader {
	if logger == nil {
		logger = func(string) {}
	}
	l := &Loader{cfg: cfg, logger: logger}
	l.logger(fmt.Sprintf("[loader] 当前平台 %s 不支持 eBPF, 完整模式受限(--dry-run 可用)", runtime.GOOS))
	return l
}

// Load 在非 Linux 平台返回受限错误。
func (l *Loader) Load() error {
	return fmt.Errorf("%w(当前平台 %s): 请使用 --dry-run 运行模拟模式, 或在 Linux(内核 >= 5.15)上运行完整模式",
		ErrUnsupportedPlatform, runtime.GOOS)
}

// ReadEvents 在非 Linux 平台立即返回受限错误。
func (l *Loader) ReadEvents(handler EventHandler) error {
	return fmt.Errorf("%w(当前平台 %s)", ErrUnsupportedPlatform, runtime.GOOS)
}

// SetAllow 实现 policy.MapSync（非 Linux 平台返回受限错误）。
func (l *Loader) SetAllow(key events.NetKey, on bool) error {
	return fmt.Errorf("%w(当前平台 %s)", ErrUnsupportedPlatform, runtime.GOOS)
}

// SetDeny 实现 policy.MapSync（非 Linux 平台返回受限错误）。
func (l *Loader) SetDeny(key events.NetKey, on bool) error {
	return fmt.Errorf("%w(当前平台 %s)", ErrUnsupportedPlatform, runtime.GOOS)
}

// SetTempAllow 实现 policy.MapSync（非 Linux 平台返回受限错误）。
func (l *Loader) SetTempAllow(key events.NetKey, on bool) error {
	return fmt.Errorf("%w(当前平台 %s)", ErrUnsupportedPlatform, runtime.GOOS)
}

// SetTaint 在非 Linux 平台返回受限错误。
func (l *Loader) SetTaint(pid uint32, dirty bool) error {
	return fmt.Errorf("%w(当前平台 %s)", ErrUnsupportedPlatform, runtime.GOOS)
}

// SetWatchPath 在非 Linux 平台返回受限错误。
func (l *Loader) SetWatchPath(idx int, prefix string) error {
	return fmt.Errorf("%w(当前平台 %s)", ErrUnsupportedPlatform, runtime.GOOS)
}

// AttachCgroup 在非 Linux 平台返回受限错误。
func (l *Loader) AttachCgroup(path string) error {
	return fmt.Errorf("%w(当前平台 %s)", ErrUnsupportedPlatform, runtime.GOOS)
}

// GovernedCgroup 在非 Linux 平台恒为空串。
func (l *Loader) GovernedCgroup() string {
	return ""
}

// Close 在非 Linux 平台是无操作。
func (l *Loader) Close() error {
	return nil
}

// IsLoaded 在非 Linux 平台恒为 false。
func (l *Loader) IsLoaded() bool {
	return false
}

// Stats 返回受限状态摘要（API /api/status 会展示）。
func (l *Loader) Stats() string {
	return fmt.Sprintf("不可用(%s 非 Linux 平台, eBPF 受限)", runtime.GOOS)
}
