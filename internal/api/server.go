// Package api 实现 Sentinel 的管理 HTTP 服务。
//
// 安全模型：审批是人的决定，被监控的 Agent 进程不得自批自准。
// 所有 /api/* 端点都要求 X-Sentinel-Token 请求头与守护进程启动时
// 生成的随机令牌一致（常量时间比较）。令牌写入 0600 权限的文件，
// 默认路径 /run/sentinel/api-token（root 可读），CLI 自动读取。
//
// 端点（除 /health 外均需鉴权）：
//   GET  /health                    健康检查（无鉴权）
//   GET  /api/status                守护进程整体状态
//   GET  /api/pending               待审批请求列表
//   POST /api/approve/{id}          批准
//   POST /api/deny/{id}             拒绝
//   POST /api/allow/add?ip&port     添加允许列表条目
//   POST /api/allow/remove?ip&port  移除允许列表条目
//   POST /api/deny/add?ip&port      添加拒绝列表条目
//   POST /api/deny/remove?ip&port   移除拒绝列表条目
//   POST /api/taint/{pid}           手动标记进程污点
//   POST /api/untaint/{pid}         手动清除进程污点
//   GET  /api/injections            凭证注入审计日志
//   GET  /api/cgroup                当前治理的 cgroup 与 freezer 状态
//   POST /api/cgroup/attach?path=   挂载被治理 cgroup（CLI cgroup 命令后端）
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sentinel-sec/sentinel/internal/approval"
	"github.com/sentinel-sec/sentinel/internal/authd"
	"github.com/sentinel-sec/sentinel/internal/freezer"
	"github.com/sentinel-sec/sentinel/internal/loader"
	"github.com/sentinel-sec/sentinel/internal/policy"
)

// StatusSource 提供状态摘要的额外信息（freezer 后端等）。
type StatusSource func() map[string]any

// Deps 是服务依赖。
type Deps struct {
	ListenAddr string               // 监听地址（如 127.0.0.1:7654）
	Manager    *approval.Manager
	Engine     *policy.Engine
	Authd      *authd.Proxy
	Loader     *loader.Loader    // 可为 nil（dry-run）；未加载时相关端点报错
	Freezer    *freezer.Freezer  // 可为 nil（freezer.enabled=false / dry-run）
	Token      string            // API 令牌（X-Sentinel-Token）
	Extra      StatusSource      // 可选的附加状态
	Logger     func(string)
}

// Server 是管理 HTTP 服务。
type Server struct {
	deps   Deps
	srv    *http.Server
	logger func(string)
}

// New 创建服务实例。
func New(deps Deps) *Server {
	logger := deps.Logger
	if logger == nil {
		logger = func(string) {}
	}
	return &Server{deps: deps, logger: logger}
}

// Start 启动 HTTP 服务（非阻塞）。
func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.handleHealth)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/status", s.handleStatus)
	apiMux.HandleFunc("/api/pending", s.handlePending)
	apiMux.HandleFunc("/api/approve/", s.handleApprove)
	apiMux.HandleFunc("/api/deny/", s.handleDeny)
	apiMux.HandleFunc("/api/allow/add", s.handleAllowAdd)
	apiMux.HandleFunc("/api/allow/remove", s.handleAllowRemove)
	apiMux.HandleFunc("/api/deny/add", s.handleDenyAdd)
	apiMux.HandleFunc("/api/deny/remove", s.handleDenyRemove)
	apiMux.HandleFunc("/api/taint/", s.handleTaint(true))
	apiMux.HandleFunc("/api/untaint/", s.handleTaint(false))
	apiMux.HandleFunc("/api/injections", s.handleInjections)
	apiMux.HandleFunc("/api/cgroup", s.handleCgroupGet)
	apiMux.HandleFunc("/api/cgroup/attach", s.handleCgroupAttach)

	mux.Handle("/api/", s.authMiddleware(apiMux))

	addr := s.deps.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:7654"
	}
	s.srv = &http.Server{Addr: addr, Handler: mux}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", addr, err)
	}
	go func() {
		s.logger(fmt.Sprintf("[api] 管理服务启动: %s", addr))
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger(fmt.Sprintf("[api] HTTP 服务错误: %v", err))
		}
	}()
	return nil
}

// Stop 优雅停止服务。
func (s *Server) Stop() {
	if s.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

// ---- 处理器 ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"ebpf":        "未加载",
		"allow_list":  []string{},
		"deny_list":   []string{},
		"temp_allow":  []policy.TempAllowEntry{},
		"pending":     0,
		"injections":  0,
		"credentials": []struct {
			ID    string
			Type  string
			Scope []string
		}{},
	}
	if s.deps.Engine != nil {
		status["allow_list"] = s.deps.Engine.GetAllowList()
		status["deny_list"] = s.deps.Engine.GetDenyList()
		status["temp_allow"] = s.deps.Engine.GetTempAllow()
	}
	if s.deps.Manager != nil {
		status["pending"] = s.deps.Manager.PendingCount()
	}
	if s.deps.Authd != nil {
		status["injections"] = len(s.deps.Authd.GetInjectionLog())
		status["credentials"] = s.deps.Authd.ListCredentials()
	}
	if s.deps.Loader != nil {
		status["ebpf"] = s.deps.Loader.Stats()
	}
	if s.deps.Extra != nil {
		for k, v := range s.deps.Extra() {
			status[k] = v
		}
	}
	writeJSON(w, status)
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.deps.Manager.PendingCards())
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/approve/")
	if err := s.deps.Manager.Approve(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	fmt.Fprintln(w, `{"status":"approved"}`)
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/deny/")
	if err := s.deps.Manager.Deny(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	fmt.Fprintln(w, `{"status":"denied"}`)
}

func (s *Server) handleAllowAdd(w http.ResponseWriter, r *http.Request) {
	s.handleListMutation(w, r, s.deps.Engine.AddAllow)
}

func (s *Server) handleAllowRemove(w http.ResponseWriter, r *http.Request) {
	s.handleListMutation(w, r, s.deps.Engine.RemoveAllow)
}

func (s *Server) handleDenyAdd(w http.ResponseWriter, r *http.Request) {
	s.handleListMutation(w, r, s.deps.Engine.AddDeny)
}

func (s *Server) handleDenyRemove(w http.ResponseWriter, r *http.Request) {
	s.handleListMutation(w, r, s.deps.Engine.RemoveDeny)
}

func (s *Server) handleListMutation(w http.ResponseWriter, r *http.Request,
	mutate func(ip string, port uint16) error) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := r.URL.Query().Get("ip")
	port, err := strconv.ParseUint(r.URL.Query().Get("port"), 10, 16)
	if err != nil || port == 0 {
		http.Error(w, "缺少有效的 ip/port 参数", http.StatusBadRequest)
		return
	}
	if err := mutate(ip, uint16(port)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, `{"status":"ok","target":"%s:%d"}`+"\n", ip, port)
}

func (s *Server) handleTaint(dirty bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		prefix := "/api/taint/"
		if !dirty {
			prefix = "/api/untaint/"
		}
		pidStr := strings.TrimPrefix(r.URL.Path, prefix)
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil || pid == 0 {
			http.Error(w, "无效 PID", http.StatusBadRequest)
			return
		}
		var state uint32
		if dirty {
			state = 1
		}
		s.deps.Engine.UpdateTaintCache(uint32(pid), state)
		if s.deps.Loader != nil && s.deps.Loader.IsLoaded() {
			if err := s.deps.Loader.SetTaint(uint32(pid), dirty); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		fmt.Fprintf(w, `{"status":"ok","pid":%d,"tainted":%v}`+"\n", pid, dirty)
	}
}

func (s *Server) handleInjections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.deps.Authd.GetInjectionLog())
}

// handleCgroupGet 返回当前治理的 cgroup 与 freezer 状态。
func (s *Server) handleCgroupGet(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"governed": "", "freezer": "未启用"}
	if s.deps.Loader != nil {
		resp["governed"] = s.deps.Loader.GovernedCgroup()
	}
	if s.deps.Freezer != nil {
		resp["freezer"] = s.deps.Freezer.Stats()
	}
	writeJSON(w, resp)
}

// handleCgroupAttach 挂载被治理 cgroup（sentinel-cli cgroup <path> 后端）：
// attach cgroup connect 钩子 + 设为 freezer 冻结目标。
func (s *Server) handleCgroupAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "缺少 path 参数(绝对路径, 如 /sys/fs/cgroup/docker/<id>)", http.StatusBadRequest)
		return
	}
	if s.deps.Loader == nil || !s.deps.Loader.IsLoaded() {
		http.Error(w, "eBPF 未加载, 无法挂载 cgroup", http.StatusServiceUnavailable)
		return
	}
	if err := s.deps.Loader.AttachCgroup(path); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.deps.Freezer != nil {
		if err := s.deps.Freezer.SetTarget(path); err != nil {
			// attach 已成功; freezer 目标失败仅降级冻结, 不影响拦截
			s.logger(fmt.Sprintf("[api] freezer 目标设置失败(冻结功能降级): %v", err))
		}
	} else {
		s.logger("[api] 警告: freezer 未启用(freezer.enabled=false), 仅拦截, 冻结不可用")
	}
	s.logger(fmt.Sprintf("[api] 治理目标已挂载: %s", path))
	fzState := "未启用"
	if s.deps.Freezer != nil {
		fzState = s.deps.Freezer.Stats()
	}
	writeJSON(w, map[string]any{"status": "ok", "governed": path, "freezer": fzState})
}

// ---- 鉴权中间件 ----

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Sentinel-Token")
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.deps.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", "X-Sentinel-Token")
			http.Error(w, "unauthorized: 缺少或错误的 X-Sentinel-Token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
