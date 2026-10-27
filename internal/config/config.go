// Package config 提供 Sentinel 配置文件的解析与校验。
//
// 为保持零外部依赖（目标环境无法访问 GitHub），这里实现了一个
// 受限的 YAML 子集解析器（见 yaml.go），支持本项目配置所需的全部语法：
// 嵌套映射、标量、字符串列表、对象列表、注释。
package config

import (
	"fmt"
	"net"
	"os"
	"time"
)

// CredentialConfig 描述一条凭证的元信息（真实值通过环境变量注入）。
type CredentialConfig struct {
	ID       string
	Type     string
	ValueEnv string // 存放真实凭证值的环境变量名
	Scope    []string
}

// Config 是 Sentinel 的完整配置。
type Config struct {
	Approval struct {
		ListenAddr        string        // 审批 HTTP 服务监听地址
		Timeout           time.Duration // 审批超时(固定语义: 超时解冻并重新进入审批)
		TokenPath         string        // API 令牌文件路径（0600）
	}

	EBPF struct {
		EnableConnect4      bool
		EnableConnect6      bool
		EnableTaintTracking bool
	}

	Policy struct {
		Allow        []string // 初始允许列表，"ip:port"
		Deny         []string // 初始拒绝列表，"ip:port"
		TempAllowTTL time.Duration
	}

	Taint struct {
		WatchPaths      []string // 受监控路径前缀（<= 8 条，每条 <= 63 字节）
		WatchExtensions []string // 保留字段：当前内核态未使用
	}

	Freezer struct {
		Enabled bool // 唯一开关。固定语义: 需要审批→冻结;
		// 批准→temp_allow+解冻; 用户拒绝→持久deny+解冻; 超时→仅解冻
	}

	Authd struct {
		Enabled      bool
		Credentials  []CredentialConfig
		SurrogateTTL time.Duration
	}

	Logging struct {
		Level  string
		Format string
		Output string
	}
}

// MaxWatchPaths 与 bpf/sentinel.bpf.c 中 MAX_WATCH_PATHS 一致。
const MaxWatchPaths = 8

// MaxWatchPathLen 与 WATCH_PATH_LEN 一致（前缀最长 63 字节 + 边界字符）。
const MaxWatchPathLen = 63

// Default 返回带默认值的配置。
func Default() Config {
	var c Config
	c.Approval.ListenAddr = "127.0.0.1:7654"
	c.Approval.Timeout = 5 * time.Minute
	c.Approval.TokenPath = "/run/sentinel/api-token"

	// 治理 cgroup 与 map pin 均无配置项: 前者由 sentinel-cli cgroup <path>
	// 运行时挂载; 后者已移除(map 不 pin, 生命周期与进程一致)
	c.EBPF.EnableConnect4 = true
	c.EBPF.EnableConnect6 = true
	c.EBPF.EnableTaintTracking = true

	c.Policy.TempAllowTTL = 5 * time.Minute
	// 过期清理周期是内部实现细节, 固定 30s(见 cmd/sentinel 的
	// tempAllowCleanupInterval), 不作为配置项暴露

	c.Taint.WatchPaths = []string{
		"/home/user/Mail",
		"/home/user/Calendar",
		"/home/user/Contacts",
		"/home/user/.ssh",
		"/home/user/.gnupg",
	}

	c.Freezer.Enabled = true

	c.Authd.Enabled = true
	c.Authd.SurrogateTTL = time.Hour

	c.Logging.Level = "info"
	c.Logging.Format = "text"
	c.Logging.Output = "stderr"
	return c
}

// Load 读取并解析配置文件，缺失字段使用默认值，最后做整体校验。
func Load(path string) (Config, error) {
	c := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("读取配置文件失败: %w", err)
	}

	tree, err := parseYAML(data)
	if err != nil {
		return c, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	if err := decode(tree, &c); err != nil {
		return c, fmt.Errorf("配置 %s 内容无效: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// decode 将解析树中的值覆盖到 Config 对应字段（仅覆盖出现的键）。
func decode(tree map[string]any, c *Config) error {
	if m := getMap(tree, "approval"); m != nil {
		c.Approval.ListenAddr = getString(m, "listen_addr", c.Approval.ListenAddr)
		c.Approval.Timeout = getDuration(m, "timeout", c.Approval.Timeout)
		c.Approval.TokenPath = getString(m, "token_path", c.Approval.TokenPath)
	}
	if m := getMap(tree, "ebpf"); m != nil {
		c.EBPF.EnableConnect4 = getBool(m, "enable_connect4", c.EBPF.EnableConnect4)
		c.EBPF.EnableConnect6 = getBool(m, "enable_connect6", c.EBPF.EnableConnect6)
		c.EBPF.EnableTaintTracking = getBool(m, "enable_taint_tracking", c.EBPF.EnableTaintTracking)
	}
	if m := getMap(tree, "policy"); m != nil {
		c.Policy.Allow = getStringList(m, "allow", c.Policy.Allow)
		c.Policy.Deny = getStringList(m, "deny", c.Policy.Deny)
		c.Policy.TempAllowTTL = getDuration(m, "temp_allow_ttl", c.Policy.TempAllowTTL)
	}
	if m := getMap(tree, "taint"); m != nil {
		c.Taint.WatchPaths = getStringList(m, "watch_paths", c.Taint.WatchPaths)
		c.Taint.WatchExtensions = getStringList(m, "watch_extensions", c.Taint.WatchExtensions)
	}
	if m := getMap(tree, "freezer"); m != nil {
		c.Freezer.Enabled = getBool(m, "enabled", c.Freezer.Enabled)
	}
	if m := getMap(tree, "authd"); m != nil {
		c.Authd.Enabled = getBool(m, "enabled", c.Authd.Enabled)
		c.Authd.SurrogateTTL = getDuration(m, "surrogate_ttl", c.Authd.SurrogateTTL)
		if items := getAnyList(m, "credentials"); items != nil {
			creds := make([]CredentialConfig, 0, len(items))
			for i, it := range items {
				cm, ok := it.(map[string]any)
				if !ok {
					return fmt.Errorf("authd.credentials[%d] 必须是映射", i)
				}
				creds = append(creds, CredentialConfig{
					ID:       getString(cm, "id", ""),
					Type:     getString(cm, "type", ""),
					ValueEnv: getString(cm, "value_env", ""),
					Scope:    getStringList(cm, "scope", nil),
				})
			}
			c.Authd.Credentials = creds
		}
	}
	if m := getMap(tree, "logging"); m != nil {
		c.Logging.Level = getString(m, "level", c.Logging.Level)
		c.Logging.Format = getString(m, "format", c.Logging.Format)
		c.Logging.Output = getString(m, "output", c.Logging.Output)
	}
	return nil
}

// Validate 校验配置的语义约束。
func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Approval.ListenAddr); err != nil {
		return fmt.Errorf("approval.listen_addr 无效: %w", err)
	}
	if c.Approval.Timeout <= 0 {
		return fmt.Errorf("approval.timeout 必须为正")
	}
	if c.Policy.TempAllowTTL <= 0 {
		return fmt.Errorf("policy.temp_allow_ttl 必须为正")
	}
	if n := len(c.Taint.WatchPaths); n > MaxWatchPaths {
		return fmt.Errorf("taint.watch_paths 最多 %d 条(内核 MAX_WATCH_PATHS 限制), 当前 %d 条",
			MaxWatchPaths, n)
	}
	for i, p := range c.Taint.WatchPaths {
		if p == "" {
			return fmt.Errorf("taint.watch_paths[%d] 为空", i)
		}
		if len(p) > MaxWatchPathLen {
			return fmt.Errorf("taint.watch_paths[%d] 超过 %d 字节: %s", i, MaxWatchPathLen, p)
		}
	}
	for _, kind := range []struct {
		name string
		list []string
	}{
		{"policy.allow", c.Policy.Allow},
		{"policy.deny", c.Policy.Deny},
	} {
		for i, e := range kind.list {
			ip, port, err := parseIPPort(e)
			if err != nil {
				return fmt.Errorf("%s[%d] 无效(应为 ip:port): %w", kind.name, i, err)
			}
			_ = ip
			_ = port
		}
	}
	for i, cred := range c.Authd.Credentials {
		if cred.ID == "" || cred.Type == "" || cred.ValueEnv == "" {
			return fmt.Errorf("authd.credentials[%d] 需要同时提供 id/type/value_env", i)
		}
	}
	return nil
}
