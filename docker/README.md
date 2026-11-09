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
| `entrypoint.sh` | 自动挂 tracefs + 环境自检（map 不 pin, 无需 bpffs） |
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
# 预期: collection 已加载(programs=6) + tracepoint×2-3 + ringbuf;
#       6.18-WSL2 内核上 fork 会显示 "已改用 fexit/kernel_clone 传播兜底"(正常降级);
#       cgroup 钩子待挂载提示

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
| 5 | 重复场景 3 后 `deny <id>` | 目标写入**持久 deny 列表** + 容器解冻; agent 重试被内核秒拒, **不再出新审批卡**; `sentinel-cli deny` 可见该条目, `deny remove` 可撤销 |
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

## 提案通道场景（UDS + SO_PEERCRED, 默认随 sentinel-verify.yaml 启用）

compose 已把共享卷 `sentinel-proposal` 挂到两容器的 `/run/sentinel-proposal`，
守护进程在其中监听 `proposal.sock`（0660, 目录 0755）。Agent 侧全程
AF_UNIX, **不触发 connect4/6 出口钩子**（可与场景矩阵同时验证互不干扰）。

```powershell
# 容器名以 docker compose ps 为准(下称 <agent>; 文档示例用 sentinel-agent)
# 注意: 双容器部署的套接字在共享卷路径, 必须 --proposal-sock 指过去
# (demo-agent 内置默认是 /run/sentinel/proposal.sock, 对应单机默认配置)
# 只读技能 → ALLOW
docker exec <agent> /tmp/demo-agent --proposal-sock /run/sentinel-proposal/proposal.sock --proposal-action INVOKE_SKILL --proposal-target gmail --proposal-scope read
# 创建连接器 → REQUIRE_USER_APPROVAL + 审批通道落卡(reason 带审批请求 ID)
docker exec <agent> /tmp/demo-agent --proposal-sock /run/sentinel-proposal/proposal.sock --proposal-action CREATE_CONNECTOR --proposal-target gmail
# 未知动作/未知凭证 → DENY(退出码 1)
docker exec <agent> /tmp/demo-agent --proposal-sock /run/sentinel-proposal/proposal.sock --proposal-action DO_EVIL --proposal-target x
```

**审批闭环**（CREATE_CONNECTOR 之后的完整流程）：

```powershell
# 1) mgmt 内: 待审列表出现提案卡(destination 显示 "CREATE_CONNECTOR gmail")
sentinel-cli pending
# 2) 用 reason 里回执的完整 request-id 批准(或 deny)
sentinel-cli approve req-<pid>-<ns>
# 3) agent 内重提案同一动作 → 直接回 ALLOW(deny 则回 DENY), 不再出新卡
docker exec <agent> /tmp/demo-agent --proposal-sock /run/sentinel-proposal/proposal.sock --proposal-action CREATE_CONNECTOR --proposal-target gmail
```

超时(approval.timeout, 验证配置 10m)不裁决：卡片消失，重提案重新等待审批。

守护进程侧逐条出现审计日志（完整链路, 无凭证/令牌明文）：

```
[proposal] 审计: req=prop-123-... uid=0 gid=0 pid=456(容器内:1) decision=ALLOW reason=只读技能调用默认放行 policy=fixed-policy-v1
```

验收清单（对应需求文档）：

| # | 验证点 | 方法 |
|---|---|---|
| 1 | 跨容器提案成功 | 上表 3 条命令在 agent 容器内均收到裁决 |
| 2 | 错误 UID 拒收 | `docker exec -u 1000 <agent> /tmp/demo-agent --proposal-action ...` → 无响应即断开; mgmt 日志出现 `身份不符: uid 不在允许列表(未读取请求体)` 且带完整 ucred |
| 3 | user namespace 映射 | agent 用 `--userns`/remap 部署时, `allowed_uids` 填**宿主 UID**(SO_PEERCRED 返回监听方命名空间视角); 验证同 #1 |
| 4 | 全程无 connect4/6 事件 | 提案运行期间 mgmt 日志无任何 `[connect] ... uid=0` 新行; 或 `bpftool prog show` 看 connect4 run_cnt 不增长 |
| 5 | 重启自动恢复 | 重启守护进程(套接字先 unlink 再 bind); agent 侧客户端容忍路径短暂消失, 稍后重试即恢复 |
| 6 | 审计完整性 | 每条提案都有 `req= uid= gid= pid= decision= reason= policy=` 字段; 令牌/凭证值不出现 |

说明: REQUEST_CREDENTIAL 在 sentinel-verify.yaml 里 authd 为关闭状态,
会返回 DENY(凭证服务未启用)——这是预期行为; 要验证替身令牌签发,
把 authd.enabled 改为 true 并配置凭证元信息后重启。

## 与单容器方案的区别（为什么这次没有那些竞态）

- 不再有 "no such process"：冻结不写 PID, 直接拨 cgroup.freeze
- 不再有 PID 命名空间翻译问题：治理单位是 cgroup, 不依赖 PID
- 审批卡不再刷屏：容器冻住后事件流停摆, 一案一卡
- sentinel 自身 egress 不被拦截：attach 的是 agent 容器

## 已知坑与排查

| 症状 | 原因与处理 |
|---|---|
| `cgroup 目录不存在` (attach 时) | mgmt 容器没带 `cgroupns: host`; 或 State.Pid 过期(容器重建过), 重新 inspect |
| tracepoint attach 失败 | tracefs 未挂载(entrypoint 自动; 手工: `mount -t tracefs none /sys/kernel/tracing`)。若失败的是 `sched_process_fork` 且日志带 "两条 perf 通道均被拒...已改用 fexit/kernel_clone 传播兜底" —— 这是 6.18-WSL2 内核已知限制的**正常降级**, 传播功能由 fexit 承接, 无需处理 |
| 启动日志含 "污点特性已停用: ... 布局校验失败" | 运行内核的 sys_enter_openat 布局与 LP64 预期不符(多为 32 位/非常规内核); 日志会给出实际 offset。其余功能(拦截/审批/冻结)不受影响 |
| openat 已挂载但无 `[taint] 标记污染` | 旧二进制(重新 `make build` + 重启); 或测试发生在旧 daemon 生命周期内。确认手段: `bpftool prog show name sentinel_taint_openat` 看 run_cnt 是否上涨 |
| attach-agent.sh 报 /proc/PID 不存在 | mgmt 未用 `pid: host`; 或 agent 容器未运行 |
| 场景 3 未冻结且无审批卡 | 目标未挂载(第 4 步漏了)——`sentinel-cli cgroup` 查看 governed 是否为空 |
| `docker stop` 冻结容器无响应 | SIGTERM 对冻结进程挂起; 用 `docker kill` 或先 approve/deny 解冻 |
| BPF collection 加载失败 `Operation not permitted` | compose 未生效(需 privileged); 内核 < 5.15 升级 Docker Desktop |
| 提案连接报 "连接提案通道失败" | 首先核对客户端路径: demo-agent 默认 `/run/sentinel/proposal.sock`(单机默认), 双容器共享卷部署必须 `--proposal-sock /run/sentinel-proposal/proposal.sock`; 其次守护进程没起 / proposal.enabled 未开 / 共享卷未挂进 agent 容器(`ls` 上述路径确认); 若守护进程刚重启, 套接字文件重建中, 客户端稍后重试即可 |
| 提案被拒 "身份不符: uid 不在允许列表" | agent 进程宿主 UID 不在 `proposal.allowed_uids`; userns/remap 部署时必须填**宿主 UID**(可用 `docker inspect -f '{{.Image}}'` 侧验证, 或直接看日志里审计行给出的 uid) |
| 启动即 "套接字目录 ... 对全局可写, 拒绝启动" | 共享卷/挂载点权限过松; `chmod o-w <目录>` 后重启(设计行为: 权限不合规宁可不起) |

## Plan B：WSL2 原生验证

容器方案受阻时, `wsl --install -d Ubuntu-24.04` 内装相同工具链直接跑
（与生产 Linux 最接近, 无任何 namespace 间接层）。
