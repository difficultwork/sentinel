// Package freezer 封装进程冻结操作，用于暂停待审批的进程。
//
// Sentinel 使用 cgroup freezer（而非 SIGSTOP）暂停待审批的进程：
//   - 被冻结进程停止调度，不占用 CPU
//   - 超时计时器同样冻结，审批耗时不影响进程自身的超时逻辑
//   - 审批通过后解冻恢复执行；拒绝后可保持冻结直到人工处置
//
// 后端选择：
//   - cgroup v2（5.15 默认）：/sys/fs/cgroup/<name>/cgroup.freeze（0/1），
//     进程写入 cgroup.procs
//   - cgroup v1 回退：freezer 控制器挂载点下 <name>/freezer.state
//     （FROZEN/THAWED），进程写入 tasks
package freezer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Freezer 管理一个 cgroup 的冻结/解冻操作。
type Freezer struct {
	backend    string // "v2" 或 "v1"
	cgroupPath string // 本 Sentinel 专用 cgroup 目录
	// v2: cgroup.freeze；v1: freezer.state
	freezeFile string
	// v2: cgroup.procs；v1: tasks
	procsFile string
	logger    func(string)
}

// New 创建 Freezer 实例。cgroupName 是 cgroup 名称（如 "sentinel_runtime"）。
func New(cgroupName string, logger func(string)) (*Freezer, error) {
	if logger == nil {
		logger = func(string) {}
	}
	if cgroupName == "" {
		cgroupName = "sentinel_runtime"
	}

	if isCgroupV2() {
		cgroupPath := filepath.Join("/sys/fs/cgroup", cgroupName)
		if err := os.MkdirAll(cgroupPath, 0755); err != nil {
			return nil, fmt.Errorf("创建 cgroup v2 目录失败: %w", err)
		}
		f := &Freezer{
			backend:    "v2",
			cgroupPath: cgroupPath,
			freezeFile: filepath.Join(cgroupPath, "cgroup.freeze"),
			procsFile:  filepath.Join(cgroupPath, "cgroup.procs"),
			logger:     logger,
		}
		f.logger(fmt.Sprintf("[freezer] cgroup v2 创建: %s", cgroupPath))
		return f, nil
	}

	root := findFreezerV1Mount()
	if root == "" {
		return nil, fmt.Errorf("未找到可用的 cgroup freezer（v2 unified 或 v1 freezer 控制器）")
	}
	cgroupPath := filepath.Join(root, cgroupName)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return nil, fmt.Errorf("创建 cgroup v1 目录失败: %w", err)
	}
	f := &Freezer{
		backend:    "v1",
		cgroupPath: cgroupPath,
		freezeFile: filepath.Join(cgroupPath, "freezer.state"),
		procsFile:  filepath.Join(cgroupPath, "tasks"),
		logger:     logger,
	}
	f.logger(fmt.Sprintf("[freezer] cgroup v1 创建: %s", cgroupPath))
	return f, nil
}

// Backend 返回当前后端（"v2" / "v1"）。
func (f *Freezer) Backend() string { return f.backend }

// CgroupPath 返回 cgroup 路径。
func (f *Freezer) CgroupPath() string { return f.cgroupPath }

// AddPID 向 cgroup 添加进程。
func (f *Freezer) AddPID(pid int) error {
	f.logger(fmt.Sprintf("[freezer] 添加进程 PID=%d 到 cgroup", pid))
	return os.WriteFile(f.procsFile, []byte(fmt.Sprintf("%d", pid)), 0644)
}

// Freeze 冻结 cgroup 内所有任务。
func (f *Freezer) Freeze() error {
	switch f.backend {
	case "v2":
		if err := os.WriteFile(f.freezeFile, []byte("1"), 0644); err != nil {
			return fmt.Errorf("冻结失败: %w", err)
		}
		return f.waitFor(func(state string) bool { return state == "1" }, 5*time.Second)
	default:
		if err := os.WriteFile(f.freezeFile, []byte("FROZEN"), 0644); err != nil {
			return fmt.Errorf("冻结失败: %w", err)
		}
		// v1 可能短暂经过 FREEZING 状态
		return f.waitFor(func(state string) bool { return state == "FROZEN" }, 5*time.Second)
	}
}

// Thaw 解冻 cgroup 内所有任务。
func (f *Freezer) Thaw() error {
	switch f.backend {
	case "v2":
		if err := os.WriteFile(f.freezeFile, []byte("0"), 0644); err != nil {
			return fmt.Errorf("解冻失败: %w", err)
		}
		return f.waitFor(func(state string) bool { return state == "0" }, 5*time.Second)
	default:
		if err := os.WriteFile(f.freezeFile, []byte("THAWED"), 0644); err != nil {
			return fmt.Errorf("解冻失败: %w", err)
		}
		return f.waitFor(func(state string) bool { return state == "THAWED" }, 5*time.Second)
	}
}

// IsFrozen 检查当前是否处于冻结状态。
func (f *Freezer) IsFrozen() (bool, error) {
	state, err := f.readState()
	if err != nil {
		return false, err
	}
	switch f.backend {
	case "v2":
		return state == "1", nil
	default:
		return state == "FROZEN", nil
	}
}

func (f *Freezer) readState() (string, error) {
	data, err := os.ReadFile(f.freezeFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// waitFor 轮询等待状态满足条件。
func (f *Freezer) waitFor(ok func(string) bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := f.readState()
		if err != nil {
			return err
		}
		if ok(state) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("等待 cgroup 冻结状态超时")
}

// Destroy 删除 cgroup（要求已解冻且无任务）。
func (f *Freezer) Destroy() error {
	_ = f.Thaw()
	f.logger(fmt.Sprintf("[freezer] 删除 cgroup: %s", f.cgroupPath))
	return os.Remove(f.cgroupPath)
}

// isCgroupV2 检测系统是否以 cgroup v2 unified 挂载。
func isCgroupV2() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// findFreezerV1Mount 查找 cgroup v1 freezer 控制器挂载点。
func findFreezerV1Mount() string {
	// 方式 1: 标准独立挂载位置
	if _, err := os.Stat("/sys/fs/cgroup/freezer/freezer.state"); err == nil {
		return "/sys/fs/cgroup/freezer"
	}
	// 方式 2: 解析 /proc/mounts
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "cgroup" {
			continue
		}
		for _, opt := range strings.Split(fields[3], ",") {
			if opt == "freezer" {
				return fields[1]
			}
		}
	}
	return ""
}
