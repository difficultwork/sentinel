# Sentinel — 内核级 AI Agent 安全网关

> 通过 eBPF 在 Linux 内核层拦截 AI Agent 的网络连接、追踪数据污点传播，
> 并在凭证离开安全边界前强制人工审批。

## 项目概述

Sentinel 是一个操作系统级安全守护系统，专为约束不可信 AI Agent 的行为而设计。
它由两层构成：

| 层 | 语言 | 职责 |
|---|---|---|
| **内核态 (eBPF)** | C (clang 18 编译，目标内核 5.15+) | connect4/connect6 拦截、污点传播追踪、ringbuf 事件上报 |
| **用户态 (Daemon)** | Go (cilium/ebpf) | 策略引擎、审批通道、cgroup freezer、凭证代理、管理 API |

**eBPF 字节码在构建期通过 `go:embed` 编入 Go 二进制**——运行时不读取
任何 `.o` 文件，部署只需单个可执行文件。

### 核心安全模型

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Host Domain (可信)                           │
│                                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐              │
│  │ 策略引擎     │  │ 审批通道      │  │ 凭证代理       │              │
│  │ (policy)    │  │ (approval)   │  │ (authd proxy) │              │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────┘              │
│         │                │                   │                      │
│  ┌──────┴────────────────┴───────────────────┴──────┐              │
│  │        Sentinel Daemon (Go, 字节码已嵌入)          │              │
│  │        管理 API (token 鉴权, 127.0.0.1:7654)      │              │
│  └──────────────────────┬───────────────────────────┘              │
│                         │ BPF ring buffer                           │
├─────────────────────────┼─────────────────────────────────────────┤
│                    内核边界 (>= 5.15)                               │
│  ┌──────────────────────┴───────────────────────────┐              │
│  │           eBPF Programs (内核态 C)                 │              │
│  │  ┌──────────┐ ┌───────────┐ ┌────────────┐       │              │
│  │  │connect4  │ │taint_fork │ │taint_openat│       │              │
│  │  │connect6  │ │cleanup    │ │(watch_map) │       │              │
│  │  └──────────┘ └───────────┘ └────────────┘       │              │
│  └──────────────────────┬───────────────────────────┘              │
│                         │                                          │
│  ┌──────────────────────┴───────────────────────────┐              │
│  │              Runtime Cell (不可信)                 │              │
│  │     AI Agent 进程 (cgroup v2/v1 freezer 管控)     │              │
│  │     ↳ 只能"提议"行动，不能自行执行敏感操作          │              │
│  └─────────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

### 决策矩阵（内核态与用户态严格一致）

| 优先级 | 条件 | 决策 |
|:---:|---|---|
| 1 | 目标在拒绝列表 | 拒绝阻断 |
| 2 | 目标在临时放行列表（人工已审批） | 放行 |
| 3 | 进程已污染（任意目标） | 需要审批 |
| 4 | 干净进程 + 允许列表 | 自动放行 |
| 5 | 未知目标 | 需要审批（deny-by-default） |

### 端到端审批闭环

```
Agent connect() → 内核阻断 + 上报 NEED_REVIEW
  → 守护进程冻结被治理容器（cgroup freezer, 进程树整体暂停）
  → 异步提交审批（不阻塞事件循环）
  → 用户: sentinel-cli approve <id>（token 鉴权）
  → 守护进程: 用户态临时放行 + 同步内核 temp_allow_map + 解冻
  → Agent 重试 connect() → 内核 temp_allow 命中 → 放行
```

## 快速开始

### 环境要求

- Linux 内核 >= 5.15（依赖：ringbuf 5.8+ / probe_read_user_str 5.5+ / 有界循环 5.3+）
- clang >= 18.0.0（编译 eBPF 字节码）
- Go >= 1.25
- root 权限（CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN）
- cgroup v2（推荐，5.15 默认）或 v1 freezer 控制器

### 编译

```bash
make toolchain   # 检查 clang/Go 版本
make build       # 编译全部：C → .o → embed → Go 二进制

# 分步
make bpf         # 仅编译 eBPF 字节码（直接输出到 internal/loader/）
make go          # 仅编译 Go 二进制（自动依赖嵌入字节码）
```

构建流水线（详见 internal/loader/README.md）——clang 把字节码直接编译进
loader 包目录，与 go:embed 就地衔接，无拷贝步骤：

```
bpf/sentinel.bpf.c --clang 18--> internal/loader/sentinel.bpf.o --go:embed--> bin/sentinel（单文件部署）
```

### 跨平台开发（Windows/macOS）

eBPF 仅存在于 Linux，但代码按平台拆分（`loader_linux.go` /
`loader_other.go`，构建标签隔离），非 Linux 平台上：

- `go build ./...`、`go vet ./...`、`go test ./...` 正常通过
- `sentinel --dry-run` 完整可用（策略引擎/审批通道/凭证代理均为纯用户态）
- 完整模式下 eBPF 相关调用返回受限错误（`loader.ErrUnsupportedPlatform`），
  守护进程降级运行并提示改用 `--dry-run`

Windows 首次编译前放置一个空的 embed 占位文件即可：
`New-Item -ItemType File internal\loader\sentinel.bpf.o`

### 本地验证（Windows + Docker Desktop）

无需 Linux 物理机：Docker Desktop 的 WSL2 内核（5.15+，cgroup v2）即可完成
全部验证。采用**双容器治理拓扑**——管理容器（sentinel 守护进程 + CLI，
privileged/cgroupns=host）与被治理容器（demo-agent），connect 拦截与冻结都以
agent 容器的 cgroup 为界（复刻生产形态；治理目标由 `sentinel-cli cgroup
<path>` 运行时挂载）。镜像与步骤见 **[docker/README.md](docker/README.md)**。

### 运行

```bash
# 模拟模式（无需 root，不加载 eBPF，验证策略引擎与审批通道）
./bin/sentinel --dry-run

# 完整模式（需要 root + 内核 5.15+）
sudo ./bin/sentinel --config configs/sentinel.yaml

# 演示 Agent
./bin/demo-agent                      # 正常 Agent
./bin/demo-agent --taint              # 受污染 Agent
./bin/demo-agent --target 1.2.3.4:80  # 指定目标
```

### 管理与审批（CLI，自动读取 /run/sentinel/api-token）

```bash
./bin/sentinel-cli status               # 守护进程整体状态
./bin/sentinel-cli pending              # 待审批请求
./bin/sentinel-cli approve <id>         # 批准（解冻 + 临时放行）
./bin/sentinel-cli deny <id>            # 拒绝（目标拉黑 + 解冻）
./bin/sentinel-cli allow 1.2.3.4 443    # 添加允许条目（同步内核 map）
./bin/sentinel-cli unallow 1.2.3.4 443  # 移除允许条目
./bin/sentinel-cli deny-list 1.2.3.4 80 # 添加拒绝条目
./bin/sentinel-cli taint 1234           # 手动标记进程污点
./bin/sentinel-cli injections           # 凭证注入审计日志
```

API 令牌解析顺序：`--token` > `$SENTINEL_API_TOKEN` > 令牌文件。
令牌由守护进程每次启动随机生成（0600 权限），被监控的 Agent 进程
无法读取，杜绝"自批自准"。

### 一键演示

```bash
./scripts/demo.sh --dry-run   # 模拟模式（无需 root）
sudo ./scripts/demo.sh        # 完整演示
```

## 项目结构

```
sentinel/
├── bpf/
│   ├── sentinel.bpf.c          # eBPF 内核态 C 源码（5.15+ 特性）
│   └── headers/bpf/            # BPF helpers 头文件
├── cmd/
│   ├── sentinel/main.go        # 守护进程入口
│   ├── sentinel-cli/main.go    # CLI 管理工具（token 鉴权）
│   └── demo-agent/main.go      # 演示用受控 Agent
├── internal/
│   ├── events/types.go         # 共享事件结构 + 二进制解码器
│   ├── config/                 # 零依赖 YAML 子集解析 + 配置校验
│   ├── policy/engine.go        # 策略引擎（决策矩阵 + 内核 map 同步）
│   ├── approval/manager.go     # 异步审批状态机
│   ├── api/server.go           # 管理 HTTP 服务（token 鉴权）
│   ├── freezer/freezer.go      # cgroup v2/v1 freezer
│   ├── authd/proxy.go          # hatch-authd 凭证代理
│   └── loader/                 # eBPF 加载器（go:embed 嵌入字节码）
│       ├── loader.go           # 共享：embed、Config、平台错误哨兵
│       ├── loader_linux.go     # Linux 完整实现（cilium/ebpf）
│       ├── loader_other.go     # 非 Linux 桩（编译通过 + 运行时受限报错）
│       ├── README.md           # embed 构建流水线 + 跨平台说明
│       └── sentinel.bpf.o      # 编译产物（clang 直接输出到本目录，make bpf 生成）
├── configs/sentinel.yaml       # 配置文件
├── scripts/demo.sh             # 演示脚本
├── Makefile                    # 构建系统
└── README.md                   # 本文件
```

## 架构详解

### 1. 连接拦截（connect4/connect6）

`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` 程序 attach 到 cgroup 的
`connect4`/`connect6` 钩子（bpf_link）。两个 hook 共用同一决策函数
`handle_connect()`，**v4/v6 走完全相同的决策矩阵**，差异仅在于从
`bpf_sock_addr` 取地址的方式。

- 拒绝/需审批的连接返回 0（connect() 立即失败），事件经 ringbuf 上报
- 三张列表 map 以双栈 `net_key`（16 字节地址 + 端口 + 协议族）为键，
  v4/v6 条目统一管理；双栈 socket 的 v4 映射地址（`::ffff:a.b.c.d`）
  在内核侧归一化为 v4，命中 v4 列表，避免误报审批
- 审批通过后目标写入 `temp_allow_map`（v4/v6 均生效），Agent 重试即放行
- attach 的 cgroup 子树即监控范围（默认 `/sys/fs/cgroup` 根）

### 2. 污点追踪

污点状态存于 BPF hash map（键 = tgid，线程级触发、进程级生效）：

- **污染触发**：`openat` 读取受监控路径前缀（`watch_map`，配置驱动，
  最多 8 条 × 63 字节，路径边界感知：`/home/u/.ssh` 不会匹配
  `/home/u/.sshx`）
- **污点传播**：`sched_process_fork` 时父进程（按 tgid，覆盖非 leader
  线程 fork 场景）污点被子进程继承
- **污点清除**：仅 leader 线程退出清除进程键；普通线程退出仅清理
  自身 tid 键——修复了旧版"任意线程退出即洗白进程污点"的逃逸漏洞

### 3. 事件上报

内核态通过 **BPF ring buffer**（16 MiB）发送事件到用户态，
用户态用逐字段小端解码器解析（无 unsafe，不受对齐差异影响）。

### 4. 审批通道（异步、防伪造）

- 独立 HTTP 服务（默认 `127.0.0.1:7654`），所有 `/api/*` 端点要求
  `X-Sentinel-Token`（常量时间比较）；令牌写入 0600 文件，仅 root 可读
- 审批提交非阻塞：请求进入待审队列 + 超时计时器（默认 5 分钟，超时解冻
  并重新进入审批）
- 审批结果经通道异步回流，对称语义：批准 → 临时放行（用户态 + 内核
  map）+ 解冻；用户拒绝 → **持久拒绝**（重试被内核直接拒绝，不再触发
  审批）+ 解冻；超时 → 仅解冻（不是对目标的裁决，重连重新进入审批）
- 事件读取循环绝不被审批阻塞

### 5. cgroup Freezer

需要审批时冻结**被治理容器整体**（`sentinel-cli cgroup <path>` 挂载的
cgroup 子树；v2: `cgroup.freeze`，v1: `freezer.state` 自动探测），Agent
进程树连同子进程一并暂停。冻结粒度是 cgroup 而非单进程——没有退出竞态、
PID 复用与 fork 逃逸问题；冻结期间进程的超时计时器同样暂停，审批耗时不
"吃掉"被冻结进程自身的超时预算。

### 6. 凭证代理（hatch-authd）

Agent 只接触 surrogate token（代理令牌）：TTL 限制（默认 1 小时）、
绑定 scope、可随时吊销、注入行为全程审计。真实凭证经环境变量注入，
不写入配置文件。

## 配置

全部行为由 configs/sentinel.yaml 驱动（缺失字段回退内置默认值，非法值
启动即报错）：审批地址/超时/令牌路径、eBPF 开关、初始允许/拒绝列表
（v4/v6 双栈，v6 条目写法 `[addr]:port`）、临时放行 TTL、受监控路径、
freezer 策略、凭证元信息（真实值走 `value_env` 环境变量）等。

## 测试

```bash
make test   # 单元测试（-race）
```

覆盖：策略决策矩阵全组合、临时放行 TTL 过期、内核 map 同步调用、
配置解析（完整语法/默认值回退/非法值拒绝）、审批状态机
（批准/拒绝/超时/重复提交/非阻塞）、事件解码器
（字段偏移/截断报错）。

## 已知限制

1. **异步重试模型**：cgroup sockaddr 钩子返回 0 时连接立即失败，Agent
   需自行重试（审批通过后重试即放行）。同步阻塞需 5.7+ 的 LSM hooks。
2. **前缀级污点**：污染在 openat 进入时标记（保守策略，读取成功与否
   不影响标记），可能产生误报。
3. **单机模式**：审批通道监听 localhost，分布式部署需额外的状态同步。
4. **冻结粒度**：按被治理 cgroup 整体冻结（通常是一个容器），同 cgroup
   内所有进程一并暂停，无法只豁免其中个别进程。

## 技术栈

| 组件 | 技术 | 版本 |
|------|------|------|
| eBPF 编译器 | clang | >= 18.0.0 |
| BPF 库 | cilium/ebpf | v0.22.0 |
| Go 编译器 | Go | >= 1.25 |
| eBPF 程序类型 | CGROUP_SOCK_ADDR + tracepoint | kernel >= 5.15 |
| 事件传输 | BPF_MAP_TYPE_RINGBUF (16 MiB) | kernel >= 5.8 |
| 污点追踪 | tracepoint (sched + syscalls) | — |
| 进程冻结 | cgroup v2 freeze / v1 freezer | v2 优先，v1 回退 |
| 字节码分发 | go:embed（构建期编入二进制） | Go >= 1.25 |

## 验证清单（目标机器）

```bash
make toolchain    # clang >= 18, Go >= 1.25
make deps         # 解析依赖并补全 go.mod/go.sum（升级 cilium/ebpf 后首次必跑）
make build        # 字节码 + 嵌入 + 二进制
make test         # 单元测试
make check        # go vet
./bin/sentinel --dry-run          # 模拟模式冒烟
sudo ./bin/sentinel               # 完整模式（观察 loader/attach 日志）
# 另一终端:
./bin/sentinel-cli status
./bin/demo-agent --taint          # 触发污点 → 连接被拦 → pending 出现
./bin/sentinel-cli approve <id>   # 解冻 + 临时放行
```

## 许可证

GPL-2.0（与 Linux 内核 eBPF 程序兼容）
