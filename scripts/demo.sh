#!/bin/bash
# Sentinel Demo 脚本
# ===================
# 演示 Sentinel 安全网关的核心功能。
#
# 用法：
#   ./scripts/demo.sh           完整演示（需要 root 加载 eBPF）
#   ./scripts/demo.sh --dry-run  模拟模式演示（无需 root）

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "========================================"
echo "  Sentinel 安全网关 - 演示脚本"
echo "========================================"
echo ""

# 颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查二进制
check_bin() {
    if [ ! -f "bin/$1" ]; then
        echo -e "${RED}错误: bin/$1 不存在${NC}"
        echo "请先运行: make build"
        exit 1
    fi
}

check_bin sentinel
check_bin sentinel-cli
check_bin demo-agent

DRY_RUN="${1:-}"

if [ "$DRY_RUN" == "--dry-run" ]; then
    echo -e "${BLUE}>>> 模拟模式(不加载 eBPF)${NC}"
    echo ""
    
    # 启动 sentinel 守护进程（模拟模式）
    echo -e "${YELLOW}>>> 启动 Sentinel 守护进程(模拟模式)...${NC}"
    ./bin/sentinel --dry-run &
    SENTINEL_PID=$!
    
    # 等待审批服务启动
    sleep 2
    
    echo ""
    echo -e "${BLUE}>>> 使用 CLI 工具查询状态${NC}"
    ./bin/sentinel-cli status || true
    
    echo ""
    echo -e "${BLUE}>>> 查看待审批请求${NC}"
    ./bin/sentinel-cli pending || true
    
    echo ""
    echo -e "${YELLOW}>>> 停止 Sentinel${NC}"
    kill $SENTINEL_PID 2>/dev/null || true
    wait $SENTINEL_PID 2>/dev/null || true
    
else
    # 检查 root
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 完整模式需要 root 权限${NC}"
        echo "请使用: sudo ./scripts/demo.sh"
        echo "或使用模拟模式: ./scripts/demo.sh --dry-run"
        exit 1
    fi
    
    # 检查 eBPF 字节码（clang 直接编译到 internal/loader/，供 go:embed 嵌入）
    if [ ! -f "internal/loader/sentinel.bpf.o" ]; then
        echo -e "${YELLOW}>>> 编译 eBPF 字节码...${NC}"
        make bpf
    fi
    
    echo -e "${YELLOW}>>> 启动 Sentinel 守护进程...${NC}"
    ./bin/sentinel &
    SENTINEL_PID=$!
    
    sleep 3
    
    echo ""
    echo -e "${BLUE}>>> 演示 1: 干净 Agent 访问允许列表目标${NC}"
    ./bin/demo-agent --target 93.184.216.34:443 --sleep 500
    
    echo ""
    echo -e "${BLUE}>>> 演示 2: 污染 Agent 尝试连接${NC}"
    ./bin/demo-agent --target 93.184.216.34:443 --taint --sleep 500
    
    echo ""
    echo -e "${BLUE}>>> 查看待审批请求${NC}"
    ./bin/sentinel-cli pending
    
    echo ""
    echo -e "${YELLOW}>>> 停止 Sentinel${NC}"
    kill $SENTINEL_PID 2>/dev/null || true
    wait $SENTINEL_PID 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  演示结束${NC}"
echo -e "${GREEN}========================================${NC}"
