// Package main 是 Sentinel 守护进程入口。
//
// Sentinel 是一个内核级 AI Agent 安全网关，通过 eBPF 在操作系统底层
// 拦截 Agent 的网络连接、追踪数据污点传播、并在凭证离开 VM 前
// 强制人工审批。
//
// 运行方式：
//   sentinel [--config configs/sentinel.yaml] [--dry-run]
//
// 需要权限：root 或 CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN
// 目标内核：>= 5.15（字节码已嵌入二进制，运行时无需 .o 文件）
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sentinel-sec/sentinel/internal/api"
	"github.com/sentinel-sec/sentinel/internal/approval"
	"github.com/sentinel-sec/sentinel/internal/authd"
	"github.com/sentinel-sec/sentinel/internal/config"
	"github.com/sentinel-sec/sentinel/internal/events"
	"github.com/sentinel-sec/sentinel/internal/freezer"
	"github.com/sentinel-sec/sentinel/internal/loader"
	"github.com/sentinel-sec/sentinel/internal/policy"
)

func main() {
	configPath := flag.String("config", "configs/sentinel.yaml", "配置文件路径")
	dryRun := flag.Bool("dry-run", false, "模拟模式: 不加载 eBPF 程序, 仅测试策略引擎与审批通道")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("========================================")
	log.Println("  Sentinel - 内核级 AI Agent 安全网关")
	log.Println("========================================")
	mode := "完整模式(eBPF)"
	if *dryRun {
		mode = "模拟模式(dry-run)"
	}
	log.Printf("模式: %s | 配置: %s", mode, *configPath)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	logger := func(msg string) { log.Println(msg) }

	// 1. 策略引擎（MapSync 在 eBPF 加载成功后注入）
	eng := policy.NewEngine(policy.Options{
		TempAllowTTL: cfg.Policy.TempAllowTTL,
		Logger:       logger,
	})

	// 2. 审批管理器（异步）+ 引擎接入
	mgr := approval.NewManager(cfg.Approval.Timeout, logger)
	eng.SetApprovalSink(func(req policy.ApprovalRequest) {
		if err := mgr.Submit(req); err != nil {
			log.Printf("[policy] 提交审批失败: %v", err)
		}
	})

	// 3. 凭证代理（真实值从环境变量注入，绝不写进配置文件）
	authProxy := authd.NewProxy(logger)
	if cfg.Authd.Enabled {
		for _, c := range cfg.Authd.Credentials {
			value := os.Getenv(c.ValueEnv)
			if value == "" {
				log.Printf("[authd] 警告: 环境变量 %s 未设置, 凭证 %s 未加载", c.ValueEnv, c.ID)
				continue
			}
			authProxy.AddCredential(c.ID, c.Type, value, c.Scope)
		}
	}

	// 4. eBPF 加载器（字节码已嵌入; cgroup 钩子由 sentinel-cli cgroup
	//    <path> 运行时挂载）
	ldr := loader.New(loader.Config{
		EnableConnect4:      cfg.EBPF.EnableConnect4,
		EnableConnect6:      cfg.EBPF.EnableConnect6,
		EnableTaintTracking: cfg.EBPF.EnableTaintTracking,
	}, logger)

	// 5. cgroup freezer（容器粒度治理；目标随 sentinel-cli cgroup <path>
	//    挂载动作一并设置）
	var fz *freezer.Freezer
	if cfg.Freezer.Enabled && !*dryRun {
		fz = freezer.New(logger)
	}

	// 6. API 令牌：每次启动随机生成，写入 0600 文件供 CLI 使用
	token, tokenPath, err := issueAPIToken(cfg.Approval.TokenPath)
	if err != nil {
		log.Fatalf("生成 API 令牌失败: %v", err)
	}
	log.Printf("API 令牌已写入: %s(CLI 将自动读取)", tokenPath)

	// 7. 管理与审批 HTTP 服务
	apiSrv := api.New(api.Deps{
		ListenAddr: cfg.Approval.ListenAddr,
		Manager:    mgr,
		Engine:     eng,
		Authd:      authProxy,
		Loader:     ldr,
		Freezer:    fz,
		Token:      token,
		Extra: func() map[string]any {
			state := "未启用"
			if fz != nil {
				state = fz.Stats()
			}
			return map[string]any{"freezer": state}
		},
		Logger: logger,
	})
	if err := apiSrv.Start(); err != nil {
		log.Fatalf("管理服务启动失败: %v", err)
	}
	defer apiSrv.Stop()

	// 8. 审批结果消费者（对称语义）: 批准 → 临时放行(含内核 map)+ 解冻;
	//    用户拒绝 → 持久拉黑 + 解冻; 超时 → 仅解冻(不改策略, 重新进入审批)
	resultDone := make(chan struct{})
	go func() {
		defer close(resultDone)
		for res := range mgr.Results() {
			handleApprovalResult(res, eng, fz, cfg)
		}
	}()

	// 9. 过期临时放行清理
	go func() {
		ticker := time.NewTicker(cfg.Policy.CleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			eng.CleanExpiredTemp()
		}
	}()

	if *dryRun {
		runDryRun(cfg, eng, mgr, authProxy)
		return
	}

	// 10. 加载 eBPF 并灌入初始策略
	if err := ldr.Load(); err != nil {
		log.Printf("警告: eBPF 加载失败: %v", err)
		if errors.Is(err, loader.ErrUnsupportedPlatform) {
			log.Println("提示: eBPF 需要 Linux(内核 >= 5.15); 当前平台请使用 --dry-run 模式运行模拟模式")
		}
		log.Println("降级运行(仅策略引擎 + 审批通道 + 凭证代理, 内核拦截不可用)")
	} else {
		log.Printf("eBPF 状态: %s", ldr.Stats())

		eng.SetMapSync(ldr)

		// 受监控路径 → 内核 watch_map
		for i, p := range cfg.Taint.WatchPaths {
			if err := ldr.SetWatchPath(i, p); err != nil {
				log.Printf("警告: 写入 watch_map[%d]=%s 失败: %v", i, p, err)
			} else {
				log.Printf("[taint] 受监控路径[%d]: %s", i, p)
			}
		}

		// 初始允许/拒绝列表 → 用户态 + 内核 map
		for _, entry := range cfg.Policy.Allow {
			if ip, port, err := splitIPPort(entry); err == nil {
				if err := eng.AddAllow(ip, port); err != nil {
					log.Printf("警告: 添加允许条目 %s 失败: %v", entry, err)
				}
			} else {
				log.Printf("警告: 配置中的允许条目 %s 无效: %v", entry, err)
			}
		}
		for _, entry := range cfg.Policy.Deny {
			if ip, port, err := splitIPPort(entry); err == nil {
				if err := eng.AddDeny(ip, port); err != nil {
					log.Printf("警告: 添加拒绝条目 %s 失败: %v", entry, err)
				}
			} else {
				log.Printf("警告: 配置中的拒绝条目 %s 无效: %v", entry, err)
			}
		}
	}
	defer ldr.Close()

	// 11. 事件处理循环（独立 goroutine，绝不被审批阻塞）
	go func() {
		handler := func(evt events.EventDesc) {
			switch evt.Type {
			case events.TypeConnect:
				ce, err := events.DecodeConnectEvent(evt.Raw)
				if err != nil {
					log.Printf("解码连接事件失败: %v", err)
					return
				}
				handleConnectEvent(&ce, eng, fz, cfg)

			case events.TypeTaintMarked, events.TypeTaintPropagate:
				te, err := events.DecodeTaintEvent(evt.Raw)
				if err != nil {
					log.Printf("解码污点事件失败: %v", err)
					return
				}
				eng.UpdateTaintCache(te.Pid, te.Taint)
				kind := "标记污染"
				if evt.Type == events.TypeTaintPropagate {
					kind = "污点传播"
				}
				log.Printf("[taint] %s: PID=%d (%s) ← 父 %d (%s)",
					kind, te.Pid, te.CommString(), te.ParentPid, te.ParentCommString())
			}
		}
		if err := ldr.ReadEvents(handler); err != nil {
			log.Printf("事件读取循环结束: %v", err)
		}
	}()

	// 12. 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("收到信号 %v, 正在退出...", sig)

	ldr.Close() // 触发 ReadEvents 返回
	apiSrv.Stop()
	select {
	case <-resultDone:
	case <-time.After(2 * time.Second):
	}
	log.Println("Sentinel 已退出")
}

// handleConnectEvent 处理一条连接事件：评估、冻结、提交审批。
func handleConnectEvent(ce *events.ConnectEvent, eng *policy.Engine,
	fz *freezer.Freezer, cfg config.Config) {

	key := ce.NetKey()
	target := key.IPPort()
	log.Printf("[connect] PID=%d (%s) → %s taint=%d 内核决策=%d",
		ce.Pid, ce.CommString(), target, ce.Taint, ce.Decision)

	decision := eng.Evaluate(ce)
	switch decision {
	case events.DecisionAllow:
		log.Printf("  决策: 放行 ✓")
		return
	case events.DecisionDeny:
		log.Printf("  决策: 拒绝 ✗")
		return
	case events.DecisionNeedReview:
		log.Printf("  决策: 需要人工审批 ⟳(冻结进程, 等待用户操作)")
	}

	// 冻结被治理容器整体（cgroup 粒度, 覆盖 Agent 进程树;
	// 冻结后容器内连接停摆, 不再产生新事件）
	if fz != nil {
		if frozen, err := fz.IsFrozen(); err == nil && frozen {
			log.Printf("  被治理容器已在冻结状态(等待审批)")
		} else if err := fz.Freeze(); err != nil {
			log.Printf("  冻结失败: %v", err)
		} else {
			log.Printf("  已冻结被治理容器(进程树整体暂停, 等待审批)")
		}
	}

	req := policy.ApprovalRequest{
		RequestID: policy.NewRequestID(ce.Pid, time.Now()),
		Pid:       ce.Pid,
		Comm:      ce.CommString(),
		DstIP:     key.IP().String(),
		DstPort:   ce.DstPort,
		Taint:     ce.Taint,
		Description: fmt.Sprintf("进程 %s (PID=%d) 请求连接到 %s(污点=%d)",
			ce.CommString(), ce.Pid, target, ce.Taint),
		Timestamp: time.Now(),
	}
	if !eng.SubmitApproval(req) {
		// 无审批通道: 对称的保守拒绝——目标拉黑 + 解冻,
		// 防止解冻后重试再次触发审批
		_ = eng.AddDeny(req.DstIP, req.DstPort)
		if fz != nil {
			_ = fz.Thaw()
		}
		log.Printf("无审批通道, 已保守拒绝: %s 拉黑并解冻", target)
	}
}

// handleApprovalResult 处理审批结果回流。
func handleApprovalResult(res approval.Result, eng *policy.Engine,
	fz *freezer.Freezer, cfg config.Config) {

	req := res.Request
	outcome := "用户拒绝"
	if res.TimedOut {
		outcome = "审批超时"
	}

	if res.Approved {
		log.Printf("[approval] 批准 %s → %s:%d 临时放行 %v",
			req.RequestID, req.DstIP, req.DstPort, cfg.Policy.TempAllowTTL)
		if err := eng.AddTempAllow(req.DstIP, req.DstPort, cfg.Policy.TempAllowTTL); err != nil {
			log.Printf("写入临时放行失败: %v", err)
		}
		if fz != nil {
			if err := fz.Thaw(); err != nil {
				log.Printf("解冻被治理容器失败: %v", err)
			} else {
				log.Printf("已解冻被治理容器(重试将命中临时放行)")
			}
		}
		return
	}

	// 用户拒绝: 政策裁决——目标写入持久 deny(重试被内核直接拒绝,
	// 不会再触发审批卡), 然后解冻容器
	log.Printf("[approval] %s %s(PID=%d)", outcome, req.RequestID, req.Pid)
	if !res.TimedOut {
		if err := eng.AddDeny(req.DstIP, req.DstPort); err != nil {
			log.Printf("写入拒绝列表失败: %v", err)
		}
	}
	if fz != nil {
		if err := fz.Thaw(); err != nil {
			log.Printf("解冻被治理容器失败: %v", err)
		} else if res.TimedOut {
			// 超时不是对目标的裁决: 不改策略, 解冻后重连将重新进入审批
			log.Printf("已解冻被治理容器(超时未裁决, %s:%d 重连将重新审批)",
				req.DstIP, req.DstPort)
		} else {
			log.Printf("已解冻被治理容器(目标 %s:%d 已拉黑, 重试将被内核拒绝)",
				req.DstIP, req.DstPort)
		}
	}
}

// runDryRun 模拟模式：不加载 eBPF，仅验证策略引擎与审批通道。
func runDryRun(cfg config.Config, eng *policy.Engine, mgr *approval.Manager, authProxy *authd.Proxy) {
	log.Println("=== 模拟模式 ===")

	for _, entry := range cfg.Policy.Allow {
		if ip, port, err := splitIPPort(entry); err == nil {
			_ = eng.AddAllow(ip, port)
		}
	}
	for _, entry := range cfg.Policy.Deny {
		if ip, port, err := splitIPPort(entry); err == nil {
			_ = eng.AddDeny(ip, port)
		}
	}

	// 演示代理令牌（如有凭证配置）
	if creds := authProxy.ListCredentials(); len(creds) > 0 {
		if token, err := authProxy.IssueSurrogate(creds[0].ID, cfg.Authd.SurrogateTTL); err == nil {
			log.Printf("[authd] 演示代理令牌: %s...", token[:20])
		}
	}

	// 模拟决策矩阵代表性组合（v4 与 v6 同一矩阵）
	ipAllowed := firstAllowed(cfg)
	tests := []events.ConnectEvent{
		{Pid: 1000, Comm: toComm("agent"), Family: events.FamilyInet, DstIP4: ipToU32(ipAllowed), DstPort: firstPort(cfg, ipAllowed), Taint: events.TaintClean},
		{Pid: 1000, Comm: toComm("agent"), Family: events.FamilyInet, DstIP4: ipToU32(firstDenied(cfg)), DstPort: denyPort(cfg), Taint: events.TaintClean},
		{Pid: 2000, Comm: toComm("tainted"), Family: events.FamilyInet, DstIP4: ipToU32(ipAllowed), DstPort: firstPort(cfg, ipAllowed), Taint: events.TaintDirty},
		{Pid: 3000, Comm: toComm("unknown"), Family: events.FamilyInet, DstIP4: ipToU32("203.0.113.9"), DstPort: 443, Taint: events.TaintClean},
		{Pid: 4000, Comm: toComm("v6agent"), Family: events.FamilyInet6, DstIP6: toIP6("2001:db8::1"), DstPort: 443, Taint: events.TaintClean},
	}

	for _, evt := range tests {
		log.Printf("--- 模拟事件: PID=%d → %s (taint=%d) ---", evt.Pid, evt.TargetString(), evt.Taint)
		switch eng.Evaluate(&evt) {
		case events.DecisionAllow:
			log.Printf("  决策: 自动放行 ✓")
		case events.DecisionDeny:
			log.Printf("  决策: 拒绝阻断 ✗")
		case events.DecisionNeedReview:
			log.Printf("  决策: 需要人工审批 ⟳(sentinel-cli pending 查看)")
		}
	}

	// 提交一条真实审批请求，供 CLI 演示 approve/deny
	demoReq := policy.ApprovalRequest{
		RequestID:   policy.NewRequestID(3000, time.Now()),
		Pid:         3000,
		Comm:        "unknown",
		DstIP:       "203.0.113.9",
		DstPort:     443,
		Taint:       events.TaintClean,
		Description: "演示: 进程 unknown (PID=3000) 请求连接到 203.0.113.9:443",
		Timestamp:   time.Now(),
	}
	if err := mgr.Submit(demoReq); err != nil {
		log.Printf("提交演示审批失败: %v", err)
	}

	log.Println("=== 模拟事件结束(守护进程保持运行, 等待审批操作) ===")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

// ---- 辅助函数 ----

// issueAPIToken 生成随机令牌并写入 0600 权限文件；/run 不可写时回退临时目录。
func issueAPIToken(path string) (token, actualPath string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("读取系统随机源失败: %w", err)
	}
	token = hex.EncodeToString(buf)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err == nil {
		if err := os.WriteFile(path, []byte(token), 0600); err == nil {
			return token, path, nil
		}
	}
	// 回退：临时目录
	fallback := filepath.Join(os.TempDir(), "sentinel-api-token")
	if err := os.WriteFile(fallback, []byte(token), 0600); err != nil {
		return "", "", fmt.Errorf("写入令牌文件失败: %w", err)
	}
	return token, fallback, nil
}

// splitIPPort 解析 "ip:port" / "[v6]:port" 配置条目。
func splitIPPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("应为 ip:port(v6 需方括号)格式: %q", s)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("端口无效: %q", portStr)
	}
	return host, uint16(port), nil
}

func ipToU32(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var v uint32
	for i := 0; i < 4; i++ {
		b, _ := strconv.Atoi(parts[i])
		v |= uint32(b&0xff) << (8 * i)
	}
	return v
}

func toIP6(s string) [16]byte {
	var b [16]byte
	copy(b[:], net.ParseIP(s).To16())
	return b
}

func toComm(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func firstAllowed(cfg config.Config) string {
	for _, e := range cfg.Policy.Allow {
		if ip, _, err := splitIPPort(e); err == nil {
			return ip
		}
	}
	return "93.184.216.34"
}

func firstPort(cfg config.Config, ip string) uint16 {
	for _, e := range cfg.Policy.Allow {
		if eip, port, err := splitIPPort(e); err == nil && eip == ip {
			return port
		}
	}
	return 443
}

func firstDenied(cfg config.Config) string {
	for _, e := range cfg.Policy.Deny {
		if ip, _, err := splitIPPort(e); err == nil {
			return ip
		}
	}
	return "1.2.3.4"
}

func denyPort(cfg config.Config) uint16 {
	for _, e := range cfg.Policy.Deny {
		if _, port, err := splitIPPort(e); err == nil {
			return port
		}
	}
	return 80
}
