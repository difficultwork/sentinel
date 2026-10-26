// Package main 是 Sentinel CLI 管理工具。
//
// 用法：
//   sentinel-cli status                查看守护进程整体状态
//   sentinel-cli pending               查看待审批请求
//   sentinel-cli approve <id>          批准审批请求
//   sentinel-cli deny <id>             拒绝审批请求
//   sentinel-cli allow <ip> <port>     添加允许列表条目
//   sentinel-cli unallow <ip> <port>   移除允许列表条目
//   sentinel-cli deny-list <ip> <port> 添加拒绝列表条目
//   sentinel-cli undeny <ip> <port>    移除拒绝列表条目
//   sentinel-cli taint <pid>           手动标记进程污点
//   sentinel-cli untaint <pid>         手动清除进程污点
//   sentinel-cli injections            查看凭证注入审计日志
//   sentinel-cli cgroup                查看当前治理的 cgroup
//   sentinel-cli cgroup <path>         挂载被治理 cgroup(拦截+冻结目标)
//                                       例: cgroup /sys/fs/cgroup/docker/<id>
//
// API 令牌解析顺序：--token > $SENTINEL_API_TOKEN > 令牌文件
// （默认 /run/sentinel/api-token，回退 $TMPDIR/sentinel-api-token）。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultAPI = "http://127.0.0.1:7654"

const defaultTokenPath = "/run/sentinel/api-token"

func main() {
	apiURL := flag.String("api", defaultAPI, "Sentinel 守护进程 API 地址")
	tokenFlag := flag.String("token", "", "API 令牌(默认从令牌文件或环境变量读取)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	token := resolveToken(*tokenFlag)
	if token == "" {
		fmt.Fprintln(os.Stderr, "错误: 未找到 API 令牌(--token, SENTINEL_API_TOKEN 或令牌文件均未提供)")
		os.Exit(1)
	}

	client := &httpClient{baseURL: *apiURL, timeout: 10 * time.Second, token: token}
	cmd := args[0]

	switch cmd {
	case "status":
		client.getAndPrint("/api/status")

	case "pending":
		client.getAndPrint("/api/pending")

	case "approve":
		if len(args) < 2 {
			fmt.Println("用法: sentinel-cli approve <request-id>")
			os.Exit(1)
		}
		client.postAndPrint("/api/approve/" + args[1])

	case "deny":
		if len(args) < 2 {
			fmt.Println("用法: sentinel-cli deny <request-id>")
			os.Exit(1)
		}
		client.postAndPrint("/api/deny/" + args[1])

	case "allow", "unallow", "deny-list", "undeny":
		if len(args) < 3 {
			fmt.Printf("用法: sentinel-cli %s <ip> <port>\n", cmd)
			os.Exit(1)
		}
		path := map[string]string{
			"allow":     "/api/allow/add",
			"unallow":   "/api/allow/remove",
			"deny-list": "/api/deny/add",
			"undeny":    "/api/deny/remove",
		}[cmd]
		client.postAndPrint(fmt.Sprintf("%s?ip=%s&port=%s", path, args[1], args[2]))

	case "taint", "untaint":
		if len(args) < 2 {
			fmt.Printf("用法: sentinel-cli %s <pid>\n", cmd)
			os.Exit(1)
		}
		client.postAndPrint("/api/" + cmd + "/" + args[1])

	case "injections":
		client.getAndPrint("/api/injections")

	case "cgroup":
		if len(args) < 2 {
			// 无参数: 查询当前治理目标
			client.getAndPrint("/api/cgroup")
			break
		}
		q := url.Values{"path": {args[1]}}
		client.postAndPrint("/api/cgroup/attach?" + q.Encode())

	default:
		fmt.Printf("未知命令: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Sentinel CLI - 管理工具

用法:
  sentinel-cli [flags] <command> [args]

命令:
  status                    查看守护进程整体状态
  pending                   查看待审批请求列表
  approve <id>              批准审批请求
  deny <id>                 拒绝审批请求
  allow <ip> <port>         添加允许列表条目
  unallow <ip> <port>       移除允许列表条目
  deny-list <ip> <port>     添加拒绝列表条目
  undeny <ip> <port>        移除拒绝列表条目
  taint <pid>               手动标记进程污点
  untaint <pid>             手动清除进程污点
  injections                查看凭证注入审计日志
  cgroup                    查看当前治理的 cgroup 与 freezer 状态
  cgroup <path>             挂载被治理 cgroup(connect 拦截 + 冻结目标)
                            例: cgroup /sys/fs/cgroup/docker/<容器id>

选项:
  -api <url>                Sentinel API 地址 (默认 http://127.0.0.1:7654)
  -token <token>            API 令牌(也可用环境变量 SENTINEL_API_TOKEN,
                            或由守护进程写入的令牌文件自动发现)`)
}

// resolveToken 按优先级解析 API 令牌。
func resolveToken(flagToken string) string {
	if flagToken != "" {
		return flagToken
	}
	if env := os.Getenv("SENTINEL_API_TOKEN"); env != "" {
		return env
	}
	candidates := []string{
		defaultTokenPath,
		filepath.Join(os.TempDir(), "sentinel-api-token"),
	}
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// httpClient 封装与 Sentinel 守护进程的 HTTP 通信（带令牌鉴权）。
type httpClient struct {
	baseURL string
	timeout time.Duration
	token   string
}

func (c *httpClient) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Sentinel-Token", c.token)
	return req, nil
}

func (c *httpClient) getAndPrint(path string) {
	req, err := c.newRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "构造请求失败: %v\n", err)
		os.Exit(1)
	}
	c.doAndPrint(req)
}

func (c *httpClient) postAndPrint(path string) {
	req, err := c.newRequest(http.MethodPost, c.baseURL+path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "构造请求失败: %v\n", err)
		os.Exit(1)
	}
	c.doAndPrint(req)
}

func (c *httpClient) doAndPrint(req *http.Request) {
	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求失败: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Fprintln(os.Stderr, "鉴权失败: 令牌无效或已过期(守护进程重启后需更新)")
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}

	// 尝试格式化 JSON
	var buf bytes.Buffer
	if json.Indent(&buf, body, "", "  ") == nil {
		fmt.Println(buf.String())
	} else {
		fmt.Println(strings.TrimSpace(string(body)))
	}
}
