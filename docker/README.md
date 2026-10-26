# Sentinel 本地验证方案（Windows + Docker Desktop，双容器治理拓扑）

在 Windows 上验证 Sentinel 全部能力，不需要 Linux 物理机。拓扑复刻生产形态：

```
Docker Desktop VM (WSL2 内核 5.15+, cgroup v2)
├─ sentinel-mgmt   管理面容器(privileged + pid:host + cgroupns:host)
│    └─ 守护进程 + CLI
│         ├─ connect4/6 attach ──┐   都指向 agent 容器的 cgroup
│         └─ freezer 冻结 ───────┘
└─ sentinel-agent  被治理容器(无特权)
     └─ demo-agent(进程树整体受拦截/冻结)
```

治理目标**不再写配置文件**：启动后用 `sentinel-cli cgroup <path>` 运行时挂载
（attach connect 钩子 + 设为 freezer 冻结目标）。冻结粒度 = 整个 agent 容器。

## 文件

| 文件 | 作用 |
|---|---|
| `Dockerfile` | 工具链镜像（clang 18 + Go 1.25 + bpftool），构建一次即可 |
| `entrypoint.sh` | 自动挂 bpffs/tracefs + 环境自检 |
| `compose.yaml` | 双容器编排（纯 image 引用，无 build 段） |
| `sentinel-verify.yaml` | 验证配置（加白回环/DNS、审批超时 10m；治理 cgroup 由 CLI 挂载） |
| `attach-agent.sh` | 在 mgmt 容器内发现 agent cgroup 并挂载 |

## 快速开始

```powershell
# 0) 镜像不存在时构建一次（Dockerfile 未变）
docker build -t sentinel:latest -f docker/Dockerfile docker/

# 1) 起两个容器（agent 常驻 sleep, mgmt 给你交互 shell）
docker compose -f docker/compose.yaml up -d
docker exec -it sentinel-mgmt bash

# 2) mgmt 容器内: 编译
#    (make deps 首次必须; 构建产物经仓库挂载对 agent 容器可见)
make toolchain && make deps && make build && make test

# 3) 启动守护进程(后台)
./bin/sentinel --config docker/sentinel-verify.yaml &
# 预期: collection 已加载 + tracepoint×3 + ringbuf; cgroup 钩子待挂载提示

# 4) 挂载治理目标(Windows 另开终端拿宿主 PID, 再回 mgmt 容器执行)
docker inspect -f '{{.State.Pid}}' sentinel-agent     # 例如 7231
./docker/attach-agent.sh 7231                          # 自动发现路径并挂载
# 预期输出: 治理目标 cgroup: /sys/fs/cgroup/.../sentinel-agent
#          [loader] cgroup hook 已 attach ×2 + [freezer] 治理目标: ...
./bin/sentinel-cli cgroup                              # 随时查看状态
```

## 场景矩阵（Windows 终端执行，agent 容器内运行）

demo-agent 经 bind mount 执行（先拷到 /tmp 保证可执行位）：

```powershell
function Agent($args) { docker exec sentinel-agent sh -c "cp /src/bin/demo-agent /tmp/ && /tmp/demo-agent $args" }
```

| # | 命令 | 预期 |
|---|---|---|
| 1 | `Agent ""` | allow 全命中, 全部连接成功 |
| 2 | `Agent "--target 1.2.3.4:80"` | deny 命中, 秒拒, 无审批卡 |
| 3 | `Agent "--target 203.0.113.9:443"` | 拦截 + **整个 agent 容器冻结** + 一张审批卡; agent 重试日志停在某个 [重试 n/60] |
| 4 | 场景 3 后: mgmt 内 `./bin/sentinel-cli pending` → `approve <id>` | 解冻容器 + temp_allow; agent 恢复重试并连接成功 |
| 5 | 重复场景 3 后 `deny <id>` | 容器保持冻结; 处置 = `docker kill sentinel-agent`（SIGKILL 对冻结任务有效） |
| 6 | `Agent "--taint --target 93.184.216.34:443"` | 读取敏感文件 → 污点事件 → 白名单目标仍被拦 → 冻结 + 审批卡 |

**冻结的可观测证据**：

```powershell
docker exec sentinel-agent ps -o pid,stat,comm     # 全部进程 STAT=D/T
docker stats --no-stream sentinel-agent            # CPU 停在 0
```

场景 3 的守护进程日志链（闭环）：

```
[connect] PID=xxx (demo-agent) → 203.0.113.9:443 taint=0 内核决策=2
  决策: 需要人工审批 ⟳
  已冻结被治理容器(进程树整体暂停, 等待审批)
[approval] 收到审批请求: ...
--- approve 后 ---
[approval] 批准 ... 临时放行 5m0s
（agent 容器恢复, demo-agent 下一轮重试连接成功）
```

## 与单容器方案的区别（为什么这次没有那些竞态）

- 不再有 "no such process"：冻结不写 PID, 直接拨 cgroup.freeze
- 不再有 PID 命名空间翻译问题：治理单位是 cgroup, 不依赖 PID
- 审批卡不再刷屏：容器冻住后事件流停摆, 一案一卡
- sentinel 自身 egress 不被拦截：attach 的是 agent 容器

## 已知坑与排查

| 症状 | 原因与处理 |
|---|---|
| `cgroup 目录不存在` (attach 时) | mgmt 容器没带 `cgroupns: host`; 或 State.Pid 过期(容器重建过), 重新 inspect |
| `pin map ...: not on a bpf filesystem` | bpffs 未挂载(entrypoint 会自动挂; 手工: `mount -t bpf bpf /sys/fs/bpf`) |
| `创建 pin 目录失败 ... no such file` | 同上 |
| tracepoint attach 失败 | tracefs 未挂载(entrypoint 自动; 手工: `mount -t tracefs none /sys/kernel/tracing`) |
| attach-agent.sh 报 /proc/PID 不存在 | mgmt 未用 `pid: host`; 或 agent 容器未运行 |
| 场景 3 未冻结且无审批卡 | 目标未挂载(第 4 步漏了)——`sentinel-cli cgroup` 查看 governed 是否为空 |
| `docker stop` 冻结容器无响应 | SIGTERM 对冻结进程挂起; 用 `docker kill` 或先 approve/deny 解冻 |
| BPF collection 加载失败 `Operation not permitted` | compose 未生效(需 privileged); 内核 < 5.15 升级 Docker Desktop |

## Plan B：WSL2 原生验证

容器方案受阻时, `wsl --install -d Ubuntu-24.04` 内装相同工具链直接跑
（与生产 Linux 最接近, 无任何 namespace 间接层）。
