package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestParseFullConfig 用完整语法的配置验证解析器。
func TestParseFullConfig(t *testing.T) {
	yaml := `
# 顶部注释
approval:
  listen_addr: "127.0.0.1:9000"   # 行尾注释
  timeout: "90s"
  auto_deny_on_timeout: false
  token_path: "/tmp/token"

ebpf:
  pin_path: "/sys/fs/bpf/x"
  cgroup_path: "/sys/fs/cgroup/y"
  enable_connect4: true
  enable_connect6: false
  enable_taint_tracking: true

policy:
  allow:
    - "10.0.0.1:443"
    - "10.0.0.2:80"
  deny:
    - "1.2.3.4:80"
  temp_allow_ttl: "2m"
  cleanup_interval: "15s"

taint:
  watch_paths:
    - "/home/user/Mail"
    - "/home/user/.ssh"
  watch_extensions:
    - ".db"
    - ".key"

freezer:
  enabled: true
  cgroup_name: "cell1"
  freeze_on_review: true
  thaw_on_approve: false
  thaw_on_deny: true

authd:
  enabled: true
  surrogate_ttl: "30m"
  credentials:
    - id: "gmail-oauth"
      type: "oauth_token"
      value_env: "ENV_A"
      scope: ["gmail.readonly"]
    - id: "calendar-api"
      type: "api_key"
      value_env: "ENV_B"
      scope:
        - "calendar.read"
        - "calendar.write"

logging:
  level: "debug"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}

	if cfg.Approval.ListenAddr != "127.0.0.1:9000" {
		t.Errorf("listen_addr = %q", cfg.Approval.ListenAddr)
	}
	if cfg.Approval.Timeout != 90*time.Second {
		t.Errorf("timeout = %v", cfg.Approval.Timeout)
	}
	if cfg.Approval.AutoDenyOnTimeout {
		t.Errorf("auto_deny_on_timeout 应为 false")
	}
	if cfg.EBPF.EnableConnect6 {
		t.Errorf("enable_connect6 应为 false")
	}
	if len(cfg.Policy.Allow) != 2 || cfg.Policy.Allow[0] != "10.0.0.1:443" {
		t.Errorf("allow = %+v", cfg.Policy.Allow)
	}
	if cfg.Policy.TempAllowTTL != 2*time.Minute {
		t.Errorf("temp_allow_ttl = %v", cfg.Policy.TempAllowTTL)
	}
	if len(cfg.Taint.WatchPaths) != 2 || cfg.Taint.WatchPaths[1] != "/home/user/.ssh" {
		t.Errorf("watch_paths = %+v", cfg.Taint.WatchPaths)
	}
	if !cfg.Freezer.ThawOnDeny || cfg.Freezer.ThawOnApprove {
		t.Errorf("freezer 开关错误: %+v", cfg.Freezer)
	}
	if cfg.Authd.SurrogateTTL != 30*time.Minute {
		t.Errorf("surrogate_ttl = %v", cfg.Authd.SurrogateTTL)
	}
	if len(cfg.Authd.Credentials) != 2 {
		t.Fatalf("credentials 数量 = %d", len(cfg.Authd.Credentials))
	}
	if cfg.Authd.Credentials[0].ID != "gmail-oauth" || cfg.Authd.Credentials[0].ValueEnv != "ENV_A" {
		t.Errorf("credentials[0] = %+v", cfg.Authd.Credentials[0])
	}
	if len(cfg.Authd.Credentials[0].Scope) != 1 || cfg.Authd.Credentials[0].Scope[0] != "gmail.readonly" {
		t.Errorf("流式列表 scope 解析错误: %+v", cfg.Authd.Credentials[0].Scope)
	}
	if len(cfg.Authd.Credentials[1].Scope) != 2 {
		t.Errorf("credentials[1].scope = %+v", cfg.Authd.Credentials[1].Scope)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("level = %q", cfg.Logging.Level)
	}
}

// TestDefaultsOnMissingFields 验证缺失字段回退默认值。
func TestDefaultsOnMissingFields(t *testing.T) {
	yaml := "approval:\n  listen_addr: \"127.0.0.1:7000\"\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "s.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Policy.TempAllowTTL != 5*time.Minute {
		t.Errorf("缺失 temp_allow_ttl 应回退默认 5m，得到 %v", cfg.Policy.TempAllowTTL)
	}
	if len(cfg.Taint.WatchPaths) != 5 {
		t.Errorf("缺失 watch_paths 应回退默认 5 条，得到 %d", len(cfg.Taint.WatchPaths))
	}
}

// TestValidateErrors 验证语义校验拦截非法配置。
func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"监听地址无效", "approval:\n  listen_addr: \"bad-addr\"\n"},
		{"超时为负", "approval:\n  timeout: \"-5m\"\n"},
		{"allow 条目缺端口", "policy:\n  allow:\n    - \"10.0.0.1\"\n"},
		{"allow 条目端口为0", "policy:\n  allow:\n    - \"10.0.0.1:0\"\n"},
		{"watch_paths 超条数", "taint:\n  watch_paths:\n    - \"/a1\"\n    - \"/a2\"\n    - \"/a3\"\n    - \"/a4\"\n    - \"/a5\"\n    - \"/a6\"\n    - \"/a7\"\n    - \"/a8\"\n    - \"/a9\"\n"},
		{"凭证缺 value_env", "authd:\n  credentials:\n    - id: \"x\"\n      type: \"api_key\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "s.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Errorf("期望校验失败，但通过了")
			}
		})
	}
}

// TestTabIndentRejected 验证 Tab 缩进被拒绝（YAML 规范）。
func TestTabIndentRejected(t *testing.T) {
	if _, err := parseYAML([]byte("a:\n\tb: 1\n")); err == nil {
		t.Errorf("Tab 缩进应报错")
	}
}

// TestParseListAtSameIndent 验证与 key 同缩进的列表语法。
func TestParseListAtSameIndent(t *testing.T) {
	tree, err := parseYAML([]byte("top:\n- " + `"x"` + "\n- \"y\"\n"))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	top, ok := tree["top"].([]any)
	if !ok || len(top) != 2 {
		t.Fatalf("top = %#v", tree["top"])
	}
	if top[0] != "x" || top[1] != "y" {
		t.Errorf("列表内容 = %#v", top)
	}
}

// TestParseEmbeddedPound 验证引号内的 # 不被当作注释。
func TestParseEmbeddedPound(t *testing.T) {
	tree, err := parseYAML([]byte("path: \"/a#b\"  # 真注释\n"))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if tree["path"] != "/a#b" {
		t.Errorf("path = %#v", tree["path"])
	}
}
