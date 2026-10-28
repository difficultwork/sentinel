//go:build linux

package loader

import "testing"

// sysEnterOpenatFormatSample 是实测自 Docker Desktop(WSL2, x86-64) 内核的
// tracefs format 原文——LP64 布局(参数区 long args[6]@16, 每参数 8 字节)。
const sysEnterOpenatFormatSample = `name: sys_enter_openat
ID: 720
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
	field:umode_t mode;	offset:40;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ...
`

func TestParseTraceFieldOffset(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		{"common_type", 0},
		{"__syscall_nr", 8},
		{"dfd", 16},
		{"filename", 24},
		{"flags", 32},
		{"mode", 40},
		{"不存在", -1},
	}
	for _, c := range cases {
		if got := parseTraceFieldOffset([]byte(sysEnterOpenatFormatSample), c.name); got != c.want {
			t.Errorf("parseTraceFieldOffset(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}
