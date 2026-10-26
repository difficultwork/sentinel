#!/bin/bash
# 发现 agent 容器的 cgroup 并挂载为 Sentinel 治理目标。
#
# 在 sentinel-mgmt 容器内执行（需 pid:host 才能读到宿主 PID 的 /proc 条目）。
#
# 用法:
#   ./docker/attach-agent.sh <宿主PID>
#   宿主PID 在 Windows 侧获取:
#     docker inspect -f '{{.State.Pid}}' sentinel-agent
set -eu

pid="${1:?用法: attach-agent.sh <宿主PID>, 即 docker inspect -f '{{.State.Pid}}' sentinel-agent 的输出}"

if [ ! -d "/proc/$pid" ]; then
    echo "错误: /proc/$pid 不存在(容器未运行, 或本容器未用 pid:host 启动)" >&2
    exit 1
fi

cg=$(awk -F: '/^0::/{print $3}' "/proc/$pid/cgroup")
if [ -z "$cg" ]; then
    echo "错误: /proc/$pid/cgroup 中无 cgroup v2 记录(0::)" >&2
    exit 1
fi

path="/sys/fs/cgroup${cg}"
if [ ! -d "$path" ]; then
    echo "错误: $path 不存在(本容器未用 cgroupns:host 启动?)" >&2
    exit 1
fi

echo "治理目标 cgroup: $path"
sentinel-cli cgroup "$path"
