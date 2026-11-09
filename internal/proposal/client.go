//go:build linux

package proposal

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Propose 以短连接提交一条提案并等待裁决(客户端, 跑在被治理容器)。
//
// 超时覆盖拨号、发送与读取全过程; 路径短暂消失(特权容器重启导致
// 套接字文件重建)由调用方通过重试本函数容忍。
func Propose(sockPath string, req Request, timeout time.Duration) (Response, error) {
	conn, err := net.DialTimeout("unix", sockPath, timeout)
	if err != nil {
		return Response{}, fmt.Errorf(
			"proposal: 连接提案通道失败(路径 %s): %w; 检查守护进程是否在跑、套接字是否挂载, 以及客户端路径是否与配置的 proposal.socket_path 一致(demo-agent 用 --proposal-sock 指定; 双容器共享卷部署通常在 /run/sentinel-proposal/proposal.sock)",
			sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeMessage(conn, &req); err != nil {
		return Response{}, err
	}
	payload, err := readMessage(conn)
	if err != nil {
		return Response{}, fmt.Errorf("proposal: 读取裁决失败: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(payload, &resp); err != nil {
		return Response{}, fmt.Errorf("proposal: 裁决解析失败: %w", err)
	}
	return resp, nil
}

// ProposeAndWait 提交提案并等待终局(无轮询):
// 若第一条裁决为 REQUIRE_USER_APPROVAL, 连接保持不动, 服务端在审批
// 落定时直接推送终局 Response。通道断开/超时时返回已收到的中间裁决
// 与说明性错误, 调用方以中间裁决为准。
func ProposeAndWait(sockPath string, req Request, timeout time.Duration) (Response, error) {
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	conn, err := net.DialTimeout("unix", sockPath, 10*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf(
			"proposal: 连接提案通道失败(路径 %s): %w; 检查守护进程是否在跑、套接字是否挂载, 以及客户端路径是否与配置的 proposal.socket_path 一致(demo-agent 用 --proposal-sock 指定; 双容器共享卷部署通常在 /run/sentinel-proposal/proposal.sock)",
			sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeMessage(conn, &req); err != nil {
		return Response{}, err
	}
	readResp := func() (Response, error) {
		payload, err := readMessage(conn)
		if err != nil {
			return Response{}, err
		}
		var r Response
		if err := json.Unmarshal(payload, &r); err != nil {
			return Response{}, fmt.Errorf("proposal: 裁决解析失败: %w", err)
		}
		return r, nil
	}

	first, err := readResp()
	if err != nil {
		return Response{}, fmt.Errorf("proposal: 读取裁决失败: %w", err)
	}
	if first.Decision != DecisionRequireUserApproval {
		return first, nil
	}
	final, err := readResp()
	if err != nil {
		return first, fmt.Errorf("proposal: 等待终局推送失败(%w), 以上面的中间裁决为准", err)
	}
	return final, nil
}
