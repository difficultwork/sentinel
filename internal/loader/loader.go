// Package loader 负责加载 eBPF 程序和 maps，并管理它们的生命周期。
//
// 字节码在构建期通过 go:embed 编译进 Go 二进制：clang 把
// bpf/sentinel.bpf.c 直接编译到本包目录的 sentinel.bpf.o（与加载器
// 同目录，无拷贝步骤，见 Makefile）。运行时不读取任何 .o 文件——
// 部署只需单个可执行文件。
//
// 平台支持：eBPF 仅存在于 Linux。本包按平台拆分实现——
//   - loader_linux.go：完整实现（目标内核 >= 5.15）
//   - loader_other.go：非 Linux 平台的桩，API 同构，调用返回
//     ErrUnsupportedPlatform（Windows/macOS 上可正常编译、可运行
//     --dry-run 模拟模式，完整模式受限）
package loader

import (
	_ "embed"
	"errors"

	"github.com/sentinel-sec/sentinel/internal/events"
)

// ErrUnsupportedPlatform 在非 Linux 平台上由桩实现返回。
// 调用方可用 errors.Is 判断并给出针对性提示。
var ErrUnsupportedPlatform = errors.New("eBPF 仅支持 Linux 平台")

// BPF 字节码在构建期嵌入。Makefile 用 clang 把 bpf/sentinel.bpf.c
// 直接编译生成本文件（编译产物，勿手工提交或编辑）。
// 非 Linux 平台开发时，放置一个空的同名文件即可满足 embed
// （字节码只在 Linux 加载路径中被读取）。
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

// EventHandler 处理从 ring buffer 读取的事件。
type EventHandler func(events.EventDesc)
