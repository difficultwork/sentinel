# Sentinel 本地验证方案（Windows + Docker Desktop）

在 Windows 上通过 Docker Desktop 验证 Sentinel 全部能力，不需要 Linux 物理机。

## 原理：为什么可行

Docker Desktop 的 Linux 容器运行在其内置 WSL2 虚拟机里（内核 5.15+ / 6.x，
带 BTF，cgroup v2）。Sentinel 对环境的要求逐项对应：

| Sentinel 要求 | Docker Desktop 提供 |
|---|---|
| 内核 >= 5.15 | WSL2 内核（`uname -r` 自检） |
| CAP_BPF / CAP_SYS_ADMIN | `privileged: true` |
| cgroup attach 点 | 容器 cgroup namespace 的 `/sys/fs/cgroup` = 本容器子树，**只拦截本容器**，天然形成隔离验证单元 |
| tracefs（污点 tracepoint） | entrypoint 按需挂载 `/sys/kernel/tracing` |
| clang 18 + Go 1.25 | 验证镜像内置（本目录 Dockerfile） |

`docker/` 目录提供四个文件：`Dockerfile`（工具链镜像）、`entrypoint.sh`
（tracefs + 自检）、`compose.yaml`（privileged 编排）、`sentinel-verify.yaml`
（容器专用配置：加白 CLI->API 回环与 Docker DNS，watch_paths 对准 demo-agent）。

## 快速开始

```powershell
# Windows PowerShell, 项目根目录
docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml run --rm sentinel-verify
# 进入容器后按下面三个阶段操作; 另开终端用:
#   docker compose -f docker/compose.yaml exec sentinel-verify bash
```

---

## 阶段 A：编译与单元测试（无需特权内容）

```bash
make toolchain   # 确认 clang >= 18 / Go >= 1.25
make deps        # 首次必须: 解析 cilium/ebpf v0.22.0 并补全 go.mod/go.sum
make build       # C -> .o -> go:embed -> 三个二进制
make test        # 单元测试(-race)
make check       # go vet
```

**通过标准**：全部命令零报错退出；`bin/` 下出现 sentinel、sentinel-cli、
demo-agent。这一步同时完成了重构后代码的首次真实编译验证。

## 阶段 B：模拟模式（dry-run，不加载 eBPF）

```bash
# 终端 1
./bin/sentinel --dry-run --config docker/sentinel-verify.yaml
```

观察决策矩阵演示输出（v4/v6 各场景的 允许/拒绝/需审批 判定），以及一条
提交给审批通道的演示请求。

```bash
# 终端 2
./bin/sentinel-cli pending                 # 看到演示请求
./bin/sentinel-cli approve <id>            # 批准
./bin/sentinel-cli status                  # 临时放行条目出现
```

**通过标准**：pending/审批/状态查询全链路工作（令牌从
/run/sentinel/api-token 自动读取）。

## 阶段 C：完整 eBPF 模式（核心验证）

> 顺序很重要：**先做完所有构建/依赖下载，再启动守护进程**。
> deny-by-default 下，容器内任何未知目标的 connect 都会被拦截并冻结——
> 包括 go build、apt、curl。CLI->API(127.0.0.1:7654) 与 Docker
> DNS(127.0.0.11:53) 已在配置中加白。

```bash
# 终端 1: 启动守护进程(root 由 privileged 提供)
./bin/sentinel --config docker/sentinel-verify.yaml
```

**启动通过标准**（日志逐条核对）：

```
[loader] collection 已加载: programs=6 maps=6
[loader] tracepoint 已 attach: sched/sched_process_fork
[loader] tracepoint 已 attach: syscalls/sys_enter_openat
[loader] tracepoint 已 attach: sched/sched_process_exit
[loader] cgroup hook 已 attach: sentinel_connect4 -> /sys/fs/cgroup
[loader] cgroup hook 已 attach: sentinel_connect6 -> /sys/fs/cgroup
[loader] ringbuf reader 已创建
[taint] 受监控路径[0]: /tmp/sentinel_demo_sensitive.txt
```

### 场景矩阵（终端 2 执行）

| # | 命令 | 预期 |
|---|---|---|
| 1 | `./bin/demo-agent` | allow 列表命中: 默认目标(example.com)与随机附加目标(google/DNS)全部连接成功 |
| 2 | `./bin/demo-agent --target 1.2.3.4:80` | deny 列表 -> 立即连接失败, 守护进程日志 `拒绝列表命中` |
| 3 | `./bin/demo-agent --target 203.0.113.9:443` | 未知目标 -> 被拦 + 进程冻结 + pending 出现审批卡 |
| 4 | 场景 3 后: `./bin/sentinel-cli pending` 再 `approve <id>` | 批准 -> 解冻; **重跑场景 3 命令** -> temp_allow 命中, 连接成功 |
| 5 | `./bin/sentinel-cli deny <另一条 pending 的 id>` | 拒绝 -> 进程**保持冻结**(thaw_on_deny=false); `kill -9 <pid>` 人工处置 |
| 6 | `./bin/demo-agent --taint --target 93.184.216.34:443` | 先读敏感文件触发污点 -> **即使在 allow 列表也被拦** -> pending; 日志出现 `[taint] 标记污染` |
| 7 | 手工污点: `bash -c 'cat /tmp/sentinel_demo_sensitive.txt; exec 3<>/dev/tcp/93.184.216.34/443'` | shell 被污染 -> /dev/tcp 连接被拦(演示任意进程污点) |

**审批闭环通过标准**（以场景 3/4 为例，守护进程日志应依次出现）：

```
[connect] PID=xxx (demo-agent) -> 203.0.113.9:443 taint=0 内核决策=2
  决策: 需要人工审批 ⟳(冻结进程, 等待用户操作)
[approval] 用户批准 req-xxx-... (PID=xxx)
[policy] 临时放行添加: 203.0.113.9:443 (TTL=5m0s)
```

冻结可观测：场景 3 发生时另开终端 `ps -o pid,stat,comm -p <pid>`，
被冻进程状态为 `D`（cgroup freezer），approve 后恢复并继续执行。

### 内核态观测（可选加分项）

```bash
bpftool prog show | grep -A2 sentinel     # 6 个程序已加载/attached
bpftool map show                          # 6 张 map, allow/deny/temp_allow 为 20 字节 net_key
bpftool map dump name allow_map           # 直接看到白名单键(十六进制 addr+port+family)
ls /sys/fs/bpf/sentinel/                  # pinned maps
```

---

## 已知坑与排查

| 症状 | 原因与处理 |
|---|---|
| `make build` 期间进程莫名被冻结 | Sentinel 已在运行(deny-by-default)。先构建后启动；或临时 `sentinel-cli allow <ip> <port>` 加白 |
| 容器内 curl/apt 全部失败 | 同上——未知目标被拦。DNS 已加白；其余目标按需加白 |
| tracepoint attach 失败 | entrypoint 挂 tracefs 失败。检查 `ls /sys/kernel/tracing/events`；不行则升级 Docker Desktop |
| freezer 初始化失败 | 宿主 cgroup 限制子组创建。功能自动降级(只拦截不冻结), 不影响拦截/审批验证 |
| `pin map to ...: not on a bpf filesystem` | `/sys/fs/bpf` 不是 bpffs 挂载点(mount 未执行/失败, 或 `compose run` 开了新容器)。容器内执行 `mount -t bpf bpf /sys/fs/bpf`; 注意 `docker compose run` 每次新建容器, 手工挂载不保留——要么 `docker compose exec` 复用同一容器, 要么重建镜像(新版 entrypoint 自动挂载) |
| `创建 pin 目录失败 ... no such file or directory` | `/sys/fs/bpf` 不存在。同上: 挂载 bpffs 即解决 |
| BPF collection 加载失败 `Operation not permitted` | 确认 compose 带 `privileged: true`; `uname -r` < 5.15 -> 升级 Docker Desktop |
| v6 场景无反应 | 容器无 v6 路由属正常; connect6 的验证看 deny 列表的 `[2001:db8::1]:443`(拦截发生在路由之前) |

## Plan B：WSL2 原生验证（容器方案受阻时）

eBPF 对 cgroup namespace / tracefs 偶有边角限制，WSL2 原生发行版是最
可靠的本地环境（与生产 Linux 几乎一致）：

```powershell
wsl --install -d Ubuntu-24.04
```

进入后在发行版内执行与 Dockerfile 相同的工具链安装（clang-18 + Go 1.25），
然后 `make build && sudo ./bin/sentinel --config configs/sentinel.yaml`。
注意原生模式下 cgroup_path 覆盖整个系统，建议把 allow 里的回环/DNS 条目
一并写入 configs/sentinel.yaml 再跑。
