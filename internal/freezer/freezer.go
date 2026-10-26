// Package freezer 封装对被治理容器(cgroup)的整体冻结/解冻。
//
// 设计（容器粒度治理）：
//   - 冻结对象是外部 cgroup（通常是 AI Agent 所在容器的 cgroup），
//     Sentinel 只拨动开关，不创建/删除/迁移任何 cgroup——目标归
//     容器运行时（docker/runc）管理。
//   - 冻结整个 cgroup 子树 = 冻结 Agent 进程树（含 MCP/工具子进程），
//     天然规避 per-PID 冻结的退出竞态、PID 复用、fork 逃逸与
//     PID 命名空间翻译问题。
//
// 后端：
//   - cgroup v2：写 <path>/cgroup.freeze（1/0）；冻结是异步操作，
//     通过 <path>/cgroup.events 的 "frozen" 字段确认实际完成
//   - cgroup v1 回退：<path>/freezer.state（FROZEN/THAWED），状态同步
package freezer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 默认状态确认超时（v2 冻结是异步的，任务可能处于不可中断睡眠）
const stateTimeout = 5 * time.Second

// Freezer 管理一个外部 cgroup 的冻结/解冻。
type Freezer struct {
	opMu    sync.Mutex // 串行化 Freeze/Thaw（并发事件可能同时触发）
	target  string     // 被治理 cgroup 的绝对路径（外部所有，勿删除）
	backend string     // "v2" / "v1"，SetTarget 时确定
	logger  func(string)
}

// New 创建 Freezer 实例。目标 cgroup 由 SetTarget 在运行期指定
// （见 sentinel-cli cgroup <path>）。
func New(logger func(string)) *Freezer {
	if logger == nil {
		logger = func(string) {}
	}
	return &Freezer{logger: logger}
}

// SetTarget 指定被治理的 cgroup（外部容器），并检测可用后端。
// 可重复调用以切换目标（切换前应先解冻旧目标）。
func (f *Freezer) SetTarget(path string) error {
	if path == "" {
		return fmt.Errorf("cgroup 路径为空")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("cgroup 路径必须是绝对路径: %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cgroup 目录不存在(在 cgroupns=host 的容器内执行?): %s: %w", path, err)
	}

	backend := "v1"
	if _, err := os.Stat(filepath.Join(path, "cgroup.freeze")); err == nil {
		backend = "v2"
	} else if _, err := os.Stat(filepath.Join(path, "freezer.state")); err != nil {
		return fmt.Errorf("%s 既无 cgroup.freeze(v2) 也无 freezer.state(v1), 不是可冻结的 cgroup", path)
	}

	f.target, f.backend = path, backend
	f.logger(fmt.Sprintf("[freezer] 治理目标: %s(后端 %s)", path, backend))
	return nil
}

// Target 返回当前治理的 cgroup 路径（未设置时为空串）。
func (f *Freezer) Target() string { return f.target }

// Backend 返回当前后端（"v2"/"v1"；未设置目标时为空串）。
func (f *Freezer) Backend() string { return f.backend }

// Freeze 冻结目标 cgroup 内全部任务（异步，等待实际生效）。
func (f *Freezer) Freeze() error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	if f.target == "" {
		return fmt.Errorf("freezer 目标未设置(先 sentinel-cli cgroup <path>)")
	}
	switch f.backend {
	case "v2":
		if err := os.WriteFile(f.freezeFile(), []byte("1"), 0644); err != nil {
			return fmt.Errorf("冻结失败: %w", err)
		}
		return f.waitForV2(1)
	default:
		if err := os.WriteFile(f.freezeFile(), []byte("FROZEN"), 0644); err != nil {
			return fmt.Errorf("冻结失败: %w", err)
		}
		return f.waitForV1("FROZEN")
	}
}

// Thaw 解冻目标 cgroup。
func (f *Freezer) Thaw() error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	if f.target == "" {
		return fmt.Errorf("freezer 目标未设置(先 sentinel-cli cgroup <path>)")
	}
	switch f.backend {
	case "v2":
		if err := os.WriteFile(f.freezeFile(), []byte("0"), 0644); err != nil {
			return fmt.Errorf("解冻失败: %w", err)
		}
		return f.waitForV2(0)
	default:
		if err := os.WriteFile(f.freezeFile(), []byte("THAWED"), 0644); err != nil {
			return fmt.Errorf("解冻失败: %w", err)
		}
		return f.waitForV1("THAWED")
	}
}

// IsFrozen 返回目标当前是否处于冻结状态。
func (f *Freezer) IsFrozen() (bool, error) {
	if f.target == "" {
		return false, fmt.Errorf("freezer 目标未设置")
	}
	switch f.backend {
	case "v2":
		return f.frozenStateV2() == 1, nil
	default:
		state, err := os.ReadFile(f.freezeFile())
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(string(state)) == "FROZEN", nil
	}
}

// Stats 返回状态摘要（供 /api/status 与日志）。
func (f *Freezer) Stats() string {
	if f.target == "" {
		return "未指定目标(用 sentinel-cli cgroup <path> 挂载)"
	}
	frozen, err := f.IsFrozen()
	if err != nil {
		return fmt.Sprintf("%s [%s] 状态未知: %v", f.target, f.backend, err)
	}
	state := "运行中"
	if frozen {
		state = "已冻结"
	}
	return fmt.Sprintf("%s [%s] %s", f.target, f.backend, state)
}

func (f *Freezer) freezeFile() string {
	if f.backend == "v2" {
		return filepath.Join(f.target, "cgroup.freeze")
	}
	return filepath.Join(f.target, "freezer.state")
}

// frozenStateV2 读取 cgroup.events 的 frozen 字段（实际状态，非请求值）。
func (f *Freezer) frozenStateV2() int {
	data, err := os.ReadFile(filepath.Join(f.target, "cgroup.events"))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "frozen" {
			if fields[1] == "1" {
				return 1
			}
			return 0
		}
	}
	return -1
}

func (f *Freezer) waitForV2(want int) error {
	deadline := time.Now().Add(stateTimeout)
	for time.Now().Before(deadline) {
		if f.frozenStateV2() == want {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("等待 cgroup frozen=%d 超时(任务可能处于不可中断睡眠): %s", want, f.target)
}

func (f *Freezer) waitForV1(want string) error {
	deadline := time.Now().Add(stateTimeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(f.freezeFile())
		if err == nil && strings.TrimSpace(string(data)) == want {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("等待 freezer.state=%s 超时: %s", want, f.target)
}
