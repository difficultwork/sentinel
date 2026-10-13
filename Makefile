# Sentinel Makefile
# ==================
#
# 工具链要求：
#   - clang >= 18.0.0（编译 eBPF 字节码，目标内核 5.15+）
#   - Go >= 1.25
#
# 目录约定：C 源码在 bpf/，编译产物直接输出到 internal/loader/（与
# Go 加载器同目录），clang 只编译一次，无拷贝步骤：
#
#   bpf/sentinel.bpf.c --clang 18--> internal/loader/sentinel.bpf.o
#                                            │ go:embed（构建期编入）
#                                            v
#                                        bin/sentinel（单文件部署，运行时不读 .o）

# 工具链（可用环境变量覆盖）
GO_BIN    ?= go
CLANG_BIN ?= clang

# 项目变量
PROJECT  := sentinel
BPF_SRC  := bpf/sentinel.bpf.c
# 编译产物与 loader 包同目录（go:embed 就地引用，无需拷贝）
BPF_OBJ  := internal/loader/sentinel.bpf.o
# 历史版本的产物路径，clean 时一并清理
BPF_OBJ_LEGACY := bpf/sentinel.bpf.o
PIN_BASE := /sys/fs/bpf/sentinel

# Go 编译参数
# export 使所有 go 子命令（build/test/vet/mod）统一生效：
# -mod=mod 允许在依赖缺失时自动补全 go.mod/go.sum
# （升级 cilium/ebpf 后首次构建会在有网环境自动拉取并记录哈希；
#   离线环境请先在有网机器执行 make deps 后再拷贝仓库）
export GOFLAGS := -trimpath -mod=mod
GO_LDFLAGS := -s -w

# clang 18 + 内核 5.15+ 编译参数：
#   -mcpu=v3            : BPF ISA v3（内核 >= 5.10），生成更优代码
#   -fno-stack-protector: 部分发行版 clang 默认开启 stack protector，BPF 不支持
BPF_CFLAGS := -O2 -g -target bpf \
	-D__TARGET_ARCH_x86 \
	-mcpu=v3 \
	-fno-stack-protector \
	-Wall -Werror \
	-Ibpf/headers

# 目标二进制
BIN_DIR := bin
BINS    := \
	$(BIN_DIR)/sentinel \
	$(BIN_DIR)/sentinel-cli \
	$(BIN_DIR)/demo-agent

# 颜色输出
ifeq ($(shell tty -s 2>/dev/null; echo $$?),0)
	C_RESET  := \033[0m
	C_GREEN  := \033[32m
	C_YELLOW := \033[33m
	C_RED    := \033[31m
	C_BLUE   := \033[34m
else
	C_RESET  :=
	C_GREEN  :=
	C_YELLOW :=
	C_RED    :=
	C_BLUE   :=
endif

.DEFAULT_GOAL := help

# ====================
# 工具链检查
# ====================

## 检查工具链版本（clang >= 18，Go >= 1.25）
.PHONY: toolchain
toolchain:
	@echo "$(C_BLUE)→ 检查工具链...$(C_RESET)"
	@$(CLANG_BIN) --version | head -1
	@$(GO_BIN) version
	@echo "$(C_GREEN)✓ 工具链检查完成（请确认 clang >= 18、Go >= 1.25）$(C_RESET)"

# ====================
# 编译目标
# ====================

## 编译 eBPF 字节码（clang 直接输出到 internal/loader/，供 go:embed 就地引用）
.PHONY: bpf
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "$(C_BLUE)→ 编译 eBPF 字节码（clang >= 18，目标内核 5.15+）...$(C_RESET)"
	@mkdir -p $(dir $@)
	$(CLANG_BIN) $(BPF_CFLAGS) -c $< -o $@
	@echo "$(C_GREEN)✓ eBPF 字节码已生成: $@$(C_RESET)"

## 编译所有 Go 二进制（自动依赖嵌入字节码）
.PHONY: go
go: $(BINS)

$(BIN_DIR)/sentinel: $(BPF_OBJ) $(wildcard cmd/sentinel/*.go) $(wildcard internal/*/*.go)
	@echo "$(C_BLUE)→ 编译 sentinel 守护进程（字节码已嵌入）...$(C_RESET)"
	@mkdir -p $(BIN_DIR)
	$(GO_BIN) build -ldflags "$(GO_LDFLAGS)" -o $@ ./cmd/sentinel
	@echo "$(C_GREEN)✓ $@$(C_RESET)"

$(BIN_DIR)/sentinel-cli: $(wildcard cmd/sentinel-cli/*.go) $(wildcard internal/*/*.go)
	@echo "$(C_BLUE)→ 编译 sentinel-cli...$(C_RESET)"
	@mkdir -p $(BIN_DIR)
	$(GO_BIN) build -ldflags "$(GO_LDFLAGS)" -o $@ ./cmd/sentinel-cli
	@echo "$(C_GREEN)✓ $@$(C_RESET)"

$(BIN_DIR)/demo-agent: $(wildcard cmd/demo-agent/*.go)
	@echo "$(C_BLUE)→ 编译 demo-agent...$(C_RESET)"
	@mkdir -p $(BIN_DIR)
	$(GO_BIN) build -ldflags "$(GO_LDFLAGS)" -o $@ ./cmd/demo-agent
	@echo "$(C_GREEN)✓ $@$(C_RESET)"

## 编译全部（eBPF 字节码 + 嵌入 + Go 二进制）
.PHONY: build
build: bpf go
	@echo "$(C_GREEN)✓ 全部编译完成（字节码已嵌入 Go 二进制）$(C_RESET)"

# ====================
# 测试目标
# ====================

## 运行 Go 单元测试（需要先有嵌入字节码）
.PHONY: test
test: $(BPF_OBJ)
	@echo "$(C_BLUE)→ 运行测试...$(C_RESET)"
	$(GO_BIN) test -race ./...

## 静态检查（vet + 编译检查，需要先有嵌入字节码）
.PHONY: check
check: $(BPF_OBJ)
	@echo "$(C_BLUE)→ 静态检查...$(C_RESET)"
	$(GO_BIN) vet ./...
	@echo "$(C_GREEN)✓ 静态检查通过$(C_RESET)"

## 格式化代码
.PHONY: fmt
fmt:
	@echo "$(C_BLUE)→ 格式化代码...$(C_RESET)"
	$(GO_BIN) fmt ./...
	@echo "$(C_GREEN)✓ 格式化完成$(C_RESET)"

# ====================
# 运行目标
# ====================

## 模拟模式运行（不加载 eBPF）
.PHONY: dry-run
dry-run: go
	@echo "$(C_YELLOW)→ 模拟模式启动...$(C_RESET)"
	$(BIN_DIR)/sentinel --dry-run

## 实际运行（需要 root 权限，内核 >= 5.15）
.PHONY: run
run: build
	@echo "$(C_YELLOW)→ Sentinel 启动...$(C_RESET)"
	sudo $(BIN_DIR)/sentinel --config configs/sentinel.yaml

## 运行 Demo Agent
.PHONY: demo
demo: go
	@echo "$(C_YELLOW)→ Demo Agent 启动...$(C_RESET)"
	$(BIN_DIR)/demo-agent

## 运行受污染的 Demo Agent
.PHONY: demo-tainted
demo-tainted: go
	@echo "$(C_YELLOW)→ 污染 Demo Agent 启动...$(C_RESET)"
	$(BIN_DIR)/demo-agent --taint

# ====================
# 清理
# ====================

## 清理编译产物（含历史路径的遗留产物）
.PHONY: clean
clean:
	@echo "$(C_RED)→ 清理...$(C_RESET)"
	rm -rf $(BIN_DIR) $(BPF_OBJ) $(BPF_OBJ_LEGACY)
	@echo "$(C_GREEN)✓ 清理完成$(C_RESET)"

## 清理 BPF pin（需要 root）
.PHONY: clean-bpf
clean-bpf:
	@echo "$(C_RED)→ 清理 BPF pin...$(C_RESET)"
	rm -rf $(PIN_BASE) 2>/dev/null || true
	@echo "$(C_GREEN)✓ BPF pin 已清理$(C_RESET)"

# ====================
# 依赖管理
# ====================

## 下载并整理 Go 依赖
.PHONY: deps
deps:
	$(GO_BIN) mod download
	$(GO_BIN) mod tidy

# ====================
# 帮助
# ====================

## 显示帮助
.PHONY: help
help:
	@echo "$(C_BLUE)==============================$(C_RESET)"
	@echo "$(C_BLUE)  Sentinel 构建系统$(C_RESET)"
	@echo "$(C_BLUE)  内核 >= 5.15 | clang >= 18 | Go >= 1.25$(C_RESET)"
	@echo "$(C_BLUE)==============================$(C_RESET)"
	@echo ""
	@echo "$(C_GREEN)编译:$(C_RESET)"
	@awk '/^## / {sub(/^## /, "  ", $$0); print}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(C_YELLOW)运行:$(C_RESET)"
	@echo "  make toolchain       检查工具链版本"
	@echo "  make dry-run         模拟模式（无需 root）"
	@echo "  make run             完整模式（需 root + 内核 5.15+）"
	@echo "  make demo            演示 Agent（允许列表内）"
	@echo "  make demo-tainted    演示污染 Agent"
	@echo ""
	@echo "$(C_RED)清理:$(C_RESET)"
	@echo "  make clean           清理编译产物（含历史路径遗留）"
	@echo "  make clean-bpf       清理 BPF pin（需 root）"
	@echo ""
	@echo "$(C_BLUE)工具链:$(C_RESET)"
	@echo "  Go:      $(GO_BIN)"
	@echo "  Clang:   $(CLANG_BIN) (要求 >= 18.0.0)"
