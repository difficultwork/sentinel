// Package main 是 Sentinel 演示 Agent，模拟一个可能失控的 AI Agent 行为。
//
// 演示场景：
//   1. 正常访问允许列表中的目标（应该自动放行）
//   2. 尝试访问未知目标（应该触发审批）
//   3. 模拟数据外泄场景（读取"敏感文件"后连接外部服务）
//
// 用法：
//   demo-agent [--target <ip:port>] [--taint] [--sleep <ms>]
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	target := flag.String("target", "93.184.216.34:443", "目标地址 ip:port")
	taint := flag.Bool("taint", false, "模拟污点: 先读取一个假敏感文件")
	sleepMs := flag.Int("sleep", 500, "每次操作间隔(毫秒)")
	retries := flag.Int("retries", 60, "连接被拦截时的最大重试次数(保持进程存活, 等待审批放行)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("=== Sentinel Demo Agent ===")
	log.Printf("目标: %s", *target)
	log.Printf("污点模拟: %v", *taint)
	log.Println()

	// 如果启用污点模拟，先"读取"一个假敏感文件
	if *taint {
		log.Println("[步骤 1] 模拟读取敏感文件 /tmp/sentinel_demo_sensitive.txt ...")
		// 实际创建临时文件模拟读取
		tmpFile := "/tmp/sentinel_demo_sensitive.txt"
		os.WriteFile(tmpFile, []byte("fake-sensitive-data"), 0644)
		data, err := os.ReadFile(tmpFile)
		if err != nil {
			log.Printf("读取失败: %v", err)
		} else {
			log.Printf("读取成功 (%d bytes): %s", len(data), string(data))
		}
		os.Remove(tmpFile)
		time.Sleep(time.Duration(*sleepMs) * time.Millisecond)
		log.Println("→ 此时进程应被 Sentinel 标记为已污染(TAINT_DIRTY)")
		log.Println()
	}

	// 尝试建立网络连接; 被拦截时保持重试存活, 演示"冻结→审批→放行"闭环。
	// (cgroup/connect4 的拦截是让 connect() 立刻失败, 并不会扣住进程;
	//  一次性拨号后退出会导致守护进程来冻结时进程已消失)
	log.Printf("[步骤 2] 尝试连接 %s ...", *target)
	var conn net.Conn
	for attempt := 1; attempt <= *retries; attempt++ {
		if attempt > 1 {
			log.Printf("[重试 %d/%d] 保持存活, 等待 Sentinel 审批放行...", attempt, *retries)
		}
		c, err := net.DialTimeout("tcp", *target, 5*time.Second)
		if err == nil {
			conn = c
			break
		}
		log.Printf("连接失败: %v", err)
		if !isConnectionRefused(err) {
			break // 超时/路由等非拦截类错误, 不重试
		}
		log.Println("→ 连接被拒绝(可能被 Sentinel 阻断, 稍后重试)")
		time.Sleep(time.Duration(*sleepMs) * time.Millisecond)
	}
	if conn != nil {
		defer conn.Close()
		log.Printf("连接成功! 本地地址: %s", conn.LocalAddr().String())

		// 发送一些数据
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: sentinel-demo\r\n\r\n")
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("读取响应失败: %v", err)
		} else {
			log.Printf("收到响应 (%d bytes): %s...", n, string(buf[:min(n, 100)]))
		}
	}

	log.Println()
	log.Println("=== 演示结束 ===")

	// 随机生成不同的连接尝试（演示多目标场景）
	if *target == "93.184.216.34:443" {
		log.Println("\n随机额外连接尝试:")
		targets := []string{
			"142.250.80.46:443", // google.com
			"1.1.1.1:53",        // cloudflare dns
			"8.8.8.8:53",        // google dns
		}
		for _, t := range targets {
			time.Sleep(time.Duration(*sleepMs) * time.Millisecond)
			log.Printf("  尝试连接 %s ...", t)
			c, err := net.DialTimeout("tcp", t, 3*time.Second)
			if err != nil {
				log.Printf("  → 失败: %v", err)
			} else {
				log.Printf("  → 成功")
				c.Close()
			}
		}
	}
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "refused") ||
		strings.Contains(msg, "blocked") ||
		strings.Contains(msg, "denied") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "not permitted") // EPERM: 部分 connect 拦截路径返回
}
