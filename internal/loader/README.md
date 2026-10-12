# loader 包构建说明

本包通过 `go:embed` 在**构建期**把 eBPF 字节码编入 Go 二进制：

```go
//go:embed sentinel.bpf.o
var sentinelBPFObj []byte
```

因此 `sentinel.bpf.o` 必须在本包目录下存在，`go build` 才能通过。
该文件是构建产物，**不要手工提交或编辑**。C 源码在 `bpf/sentinel.bpf.c`，
Makefile 用 clang 把它**直接编译到本目录**（与加载器同目录，无拷贝步骤）：

```
bpf/sentinel.bpf.c --clang 18--> internal/loader/sentinel.bpf.o --go:embed--> bin/sentinel
```

## 常用命令

- `make bpf`    只编译字节码（直接输出到本目录）
- `make build`  编译全部（字节码 + 嵌入 + Go 二进制）
- `make test`   运行测试（自动先生成字节码）

## 为什么不用仓库里现成的 .o？

字节码必须与 `bpf/sentinel.bpf.c` 严格同步。若放置一份过期的 .o，
`go build` 会把旧内核逻辑静默编入二进制，造成难以排查的行为漂移。
让 embed 依赖 Makefile 生成（缺少时构建报错），可确保二进制内的
字节码总是来自当前 C 源码、且由正确的 clang 版本（>= 18，目标内核
5.15+）编译。

## 部署

得益于 embed，生产部署只需拷贝 `bin/sentinel` 单个文件（目标机器
无需 clang、无需 .o 文件，仅需 root 权限与内核 >= 5.15）。
