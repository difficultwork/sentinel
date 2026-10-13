module github.com/sentinel-sec/sentinel

go 1.25.0

require github.com/cilium/ebpf v0.22.0

require golang.org/x/sys v0.43.0 // indirect

// 间接依赖（golang.org/x/sys 等）的精确版本与 go.sum 哈希
// 由 `make deps`（go mod tidy）在目标机器上解析写入；
// Makefile 已导出 GOFLAGS=-mod=mod，直接 `make build` 亦会自动补全。
