#!/bin/bash
# 容器入口：挂载 tracefs（tracepoint 需要）+ 环境自检
set -u

# cgroup sockaddr 钩子由 --privileged 提供；tracepoint 需要 tracefs。
# Docker Desktop 的 VM 通常已挂载, 容器内未必可见, 这里按需挂载。
if ! mountpoint -q /sys/kernel/tracing 2>/dev/null; then
    mkdir -p /sys/kernel/tracing 2>/dev/null
    mount -t tracefs none /sys/kernel/tracing 2>/dev/null \
        || echo "[entrypoint] 警告: tracefs 挂载失败, 污点追踪 tracepoint 将不可用"
fi

# BPF 文件系统(map pin 必须落在 bpffs 上): 容器内默认没有, 需要挂载。
# 普通目录会报 "pin map to ...: not on a bpf filesystem"。
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    mkdir -p /sys/fs/bpf 2>/dev/null
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null \
        || echo "[entrypoint] 警告: bpffs 挂载失败, eBPF map pin 将不可用(手工执行: mount -t bpf bpf /sys/fs/bpf)"
fi

echo "== Sentinel 验证环境自检 =="
echo "内核:   $(uname -r)"
kver=$(uname -r | cut -d. -f1-2 | tr -d '.')
if [ "${kver:-0}" -lt 515 ] 2>/dev/null; then
    kmajor=$(uname -r | cut -d. -f1)
    if [ "${kmajor:-0}" -lt 6 ] 2>/dev/null; then
        echo "警告:   内核版本可能低于 5.15, 请升级 Docker Desktop"
    fi
fi
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "BTF:    OK (/sys/kernel/btf/vmlinux)"
else
    echo "BTF:    缺失(CO-RE 模式, 可能影响加载)"
fi
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ]; then
    echo "cgroup: v2(unified)"
else
    echo "cgroup: 非 v2(freezer 将回退 v1 或降级)"
fi
if [ "$(stat -fc %T /sys/fs/bpf 2>/dev/null)" = "bpf" ]; then
    echo "bpffs:  OK (/sys/fs/bpf)"
else
    echo "bpffs:  未挂载(完整模式需要: mount -t bpf bpf /sys/fs/bpf)"
fi
if [ -d /sys/kernel/tracing/events/sched ]; then
    echo "trace:  OK (/sys/kernel/tracing)"
else
    echo "trace:  不可用(污点追踪将降级)"
fi
clang --version | head -1
go version
echo "================================"
echo "提示: 完整验证步骤见 docker/README.md"
echo "================================"

exec "$@"
