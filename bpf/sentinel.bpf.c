// SPDX-License-Identifier: GPL-2.0
// sentinel.bpf.c — Sentinel eBPF 内核态程序
//
// 目标环境：Linux >= 5.15，clang >= 18（-O2 -mcpu=v3）
//
// 使用的 5.15+ 可用特性：
//   - BPF_MAP_TYPE_RINGBUF（5.8+）替代 perf event array，更低开销、跨 CPU 聚合
//   - bpf_probe_read_user_str（5.5+）安全读取用户态路径
//   - bpf_get_current_cgroup_id（4.18+）无条件使用，事件携带 64 位 cgroup id
//   - 有界循环（5.3+ 验证器）实现可配置路径前缀匹配，替代硬编码逐字节比较
//   - LIBBPF_PIN_BY_NAME map 持久化
//
// 拦截策略（与用户态 policy.Engine.Evaluate 严格一致）：
//   1. 拒绝列表           → 阻断 + 上报 EVENT_CONNECT(DENY)
//   2. 临时放行（已审批）  → 放行（人工审批优先于污点判定）
//   3. 进程已污染          → 阻断 + 上报 EVENT_CONNECT(NEED_REVIEW)
//   4. 永久允许列表        → 放行
//   5. 未知目标            → 阻断 + 上报 EVENT_CONNECT(NEED_REVIEW)（deny-by-default）
//
// 污点键约定：
//   - taint_map 的键 = 线程组 ID（tgid），connect 钩子按 tgid 查询，
//     线程内任一触发的污染对整个进程生效。
//   - fork 传播：父键取 current 的 tgid（覆盖非 leader 线程 fork 的场景），
//     子键取 tracepoint 的 child_pid（对 fork() 恰为其 tgid；
//     对 pthread_create 产生的线程键无害，且在对应线程退出时被清理）。
//   - 退出清理：leader 退出清 tgid 键，普通线程退出清自身 tid 键，
//     修复了“任意线程退出清除整个进程污点”的逃逸漏洞。

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/sched.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* ====== 常量 ====== */
#define TAINT_MAP_MAX_ENTRIES 65536
#define ALLOW_MAP_MAX_ENTRIES 8192
#define RINGBUF_SIZE (1 << 24)          /* 16 MiB */
#define MAX_WATCH_PATHS 8               /* 受监控路径前缀条数上限 */
#define WATCH_PATH_LEN 64               /* 单条前缀最大长度（含边界检查用字符） */

/* ====== 共享数据结构（必须与 internal/events/types.go 保持布局一致）====== */

enum sentinel_event_type {
    EVENT_CONNECT         = 1,
    EVENT_TAINT_MARKED    = 2,
    EVENT_TAINT_PROPAGATE = 3,
};

enum sentinel_decision {
    DECISION_ALLOW       = 0,
    DECISION_DENY        = 1,
    DECISION_NEED_REVIEW = 2,
};

enum taint_state {
    TAINT_CLEAN = 0,
    TAINT_DIRTY = 1,
};

/* connect 事件：显式对齐填充，总大小 80 字节 */
struct connect_event {
    __u32 type;          /*  0 */
    __u32 pid;           /*  4  tgid */
    __u32 tgid;          /*  8 */
    __u32 uid;           /* 12 */
    __u64 cgroup_id;     /* 16  64 位 cgroup v2 id */
    __u32 family;        /* 24 */
    __u32 protocol;      /* 28 */
    __u32 dst_ip4;       /* 32  网络字节序 */
    __u8  dst_ip6[16];   /* 36 */
    __u16 dst_port;      /* 52  主机字节序 */
    __u16 _pad;          /* 54 */
    __u32 taint;         /* 56 */
    __u32 decision;      /* 60 */
    char  comm[16];      /* 64 */
};                       /* 80 */

/* taint 事件：全部 4 字节对齐标量 + 字节数组，总大小 52 字节，无隐式填充 */
struct taint_event {
    __u32 type;          /*  0 */
    __u32 pid;           /*  4 */
    __u32 parent_pid;    /*  8 */
    __u32 uid;           /* 12 */
    __u32 taint;         /* 16 */
    char  comm[16];      /* 20 */
    char  parent_comm[16]; /* 36 */
};                       /* 52 */

/* tracepoint: sched_process_fork 上下文 */
struct sched_process_fork_ctx {
    char  parent_comm[16];
    __u32 parent_pid;
    __u32 parent_prio;
    char  child_comm[16];
    __u32 child_pid;
    __u32 child_prio;
};

/* tracepoint: sys_enter_openat 上下文 */
struct sys_enter_openat_ctx {
    __u64 __syscall_nr;
    __s64 dfd;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

/* 受监控路径前缀（由用户态从配置写入 watch_map） */
struct watch_path {
    char prefix[WATCH_PATH_LEN];
    __u32 len;           /* 前缀有效长度，<= WATCH_PATH_LEN - 1 */
};

/* ====== BPF Maps ====== */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);        /* tgid */
    __type(value, __u32);      /* enum taint_state */
    __uint(max_entries, TAINT_MAP_MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} taint_map SEC(".maps");

struct allow_key {
    __u32 ip4;           /* 网络字节序 */
    __u16 port;          /* 主机字节序 */
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct allow_key);
    __type(value, __u32);
    __uint(max_entries, ALLOW_MAP_MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct allow_key);
    __type(value, __u32);
    __uint(max_entries, ALLOW_MAP_MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} deny_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct allow_key);
    __type(value, __u32);
    __uint(max_entries, ALLOW_MAP_MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} temp_allow_map SEC(".maps");

/* 受监控路径表：key = 数组下标，value = 前缀。用户态启动时写入 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct watch_path);
    __uint(max_entries, MAX_WATCH_PATHS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} watch_map SEC(".maps");

/* 事件环形缓冲区（不 pin，每次启动由用户态重建 reader） */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/* ====== 辅助函数 ====== */

static __always_inline __u32 get_taint(__u32 tgid)
{
    __u32 *val = bpf_map_lookup_elem(&taint_map, &tgid);
    if (val)
        return *val;
    return TAINT_CLEAN;
}

static __always_inline void fill_connect_common(struct connect_event *e,
                                                __u32 tgid, __u32 uid,
                                                __u64 cgid, __u32 family,
                                                __u16 port, __u32 taint,
                                                __u32 decision)
{
    e->type = EVENT_CONNECT;
    e->pid = tgid;
    e->tgid = tgid;
    e->uid = uid;
    e->cgroup_id = cgid;
    e->family = family;
    e->protocol = 0;
    e->dst_port = port;
    e->taint = taint;
    e->decision = decision;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ====== 模块 1: connect 拦截 ====== */

SEC("cgroup/connect4")
int sentinel_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->family != AF_INET)
        return 1;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();

    __u32 dst_ip4 = ctx->user_ip4;
    __u16 dst_port = __bpf_ntohs(ctx->user_port);

    struct allow_key akey = {
        .ip4 = dst_ip4,
        .port = dst_port,
    };

    __u32 taint = get_taint(tgid);

    /* 1. 拒绝列表 → 立即阻断 */
    if (bpf_map_lookup_elem(&deny_map, &akey)) {
        struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_connect_common(e, tgid, uid, cgid, ctx->family, dst_port,
                                taint, DECISION_DENY);
            e->dst_ip4 = dst_ip4;
            bpf_ringbuf_submit(e, 0);
        }
        return 0;
    }

    /* 2. 临时放行（人工审批已通过）→ 放行。审批是人的决定，优先于污点判定 */
    if (bpf_map_lookup_elem(&temp_allow_map, &akey))
        return 1;

    /* 3. 已污染进程 → 任何目标都需要审批（无论是否在允许列表） */
    if (taint == TAINT_DIRTY) {
        struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_connect_common(e, tgid, uid, cgid, ctx->family, dst_port,
                                TAINT_DIRTY, DECISION_NEED_REVIEW);
            e->dst_ip4 = dst_ip4;
            bpf_ringbuf_submit(e, 0);
        }
        return 0;
    }

    /* 4. 永久允许列表 → 放行 */
    if (bpf_map_lookup_elem(&allow_map, &akey))
        return 1;

    /* 5. 未知目标 → 阻断并请求审批（deny-by-default） */
    {
        struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_connect_common(e, tgid, uid, cgid, ctx->family, dst_port,
                                taint, DECISION_NEED_REVIEW);
            e->dst_ip4 = dst_ip4;
            bpf_ringbuf_submit(e, 0);
        }
        return 0;
    }
}

/*
 * connect6：v6 目标不参与 IP 级允许/拒绝列表（map 以 v4 为键），
 * 仅对已污染进程强制审批；干净进程放行。已知限制，见 README。
 */
SEC("cgroup/connect6")
int sentinel_connect6(struct bpf_sock_addr *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 taint = get_taint(tgid);

    if (taint != TAINT_DIRTY)
        return 1;

    __u32 uid = bpf_get_current_uid_gid() >> 32;
    __u64 cgid = bpf_get_current_cgroup_id();
    __u16 dst_port = __bpf_ntohs(ctx->user_port);

    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        fill_connect_common(e, tgid, uid, cgid, ctx->family, dst_port,
                            TAINT_DIRTY, DECISION_NEED_REVIEW);
        __builtin_memcpy(e->dst_ip6, ctx->user_ip6, sizeof(e->dst_ip6));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* ====== 模块 2: 污点传播 ====== */

/*
 * 判断 openat 路径是否命中受监控前缀。
 * 匹配规则：前缀完全匹配，且路径在前缀结束后要么结束、要么是 '/'，
 * 避免 "/home/user/.ssh" 误匹配 "/home/user/.ssh.config"。
 * 所有循环均为常量上界，5.3+ 验证器可直接接受。
 */
static __always_inline int is_watched_path(const char *path, __u32 plen)
{
    for (int i = 0; i < MAX_WATCH_PATHS; i++) {
        __u32 idx = (__u32)i;
        struct watch_path *wp = bpf_map_lookup_elem(&watch_map, &idx);
        if (!wp)
            continue;

        __u32 len = wp->len;
        if (len == 0 || len > WATCH_PATH_LEN - 1 || len > plen)
            continue;

        int match = 1;
        for (__u32 j = 0; j < WATCH_PATH_LEN - 1; j++) {
            if (j >= len)
                break;
            if (path[j] != wp->prefix[j]) {
                match = 0;
                break;
            }
        }
        if (!match)
            continue;

        /* 边界检查：前缀后必须是路径分隔符或字符串结尾 */
        if (len == plen || path[len] == '/')
            return 1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sentinel_taint_openat(struct sys_enter_openat_ctx *ctx)
{
    __u32 flags = (__u32)ctx->flags;

    /* 只关心读语义的打开（O_WRONLY=1 / O_RDWR=2 则跳过） */
    if ((flags & 0x3) != 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() >> 32;

    if (get_taint(tgid) == TAINT_DIRTY)
        return 0;

    char path[WATCH_PATH_LEN] = {};
    long n = bpf_probe_read_user_str(path, sizeof(path), ctx->filename);
    if (n <= 1) /* 出错或空串（n 含结尾 NUL） */
        return 0;
    __u32 plen = (__u32)n - 1;

    if (!is_watched_path(path, plen))
        return 0;

    /* 标记污点并上报 */
    __u32 dirty = TAINT_DIRTY;
    bpf_map_update_elem(&taint_map, &tgid, &dirty, BPF_ANY);

    struct taint_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_TAINT_MARKED;
        e->pid = tgid;
        e->parent_pid = 0;
        e->uid = uid;
        e->taint = TAINT_DIRTY;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/*
 * fork 污点传播：
 *   - 父键用 current 的 tgid（bpf_get_current_pid_tgid >> 32），
 *     覆盖“非 leader 线程调用 fork()”的场景；
 *   - 子键用 tracepoint 的 child_pid：fork() 时即子进程 tgid，
 *     pthread_create 时是线程 tid（查询侧从不使用，退出时清理）。
 */
SEC("tracepoint/sched/sched_process_fork")
int sentinel_taint_fork(struct sched_process_fork_ctx *ctx)
{
    __u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 child_pid = ctx->child_pid;

    __u32 *parent_taint = bpf_map_lookup_elem(&taint_map, &parent_tgid);
    if (!parent_taint || *parent_taint != TAINT_DIRTY)
        return 0;

    __u32 dirty = TAINT_DIRTY;
    bpf_map_update_elem(&taint_map, &child_pid, &dirty, BPF_ANY);

    struct taint_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_TAINT_PROPAGATE;
        e->pid = child_pid;
        e->parent_pid = parent_tgid;
        e->uid = bpf_get_current_uid_gid() >> 32;
        e->taint = TAINT_DIRTY;
        __builtin_memcpy(e->comm, ctx->child_comm, sizeof(e->comm));
        __builtin_memcpy(e->parent_comm, ctx->parent_comm, sizeof(e->parent_comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/*
 * 进程退出清理：
 *   - leader 退出（pid == tgid）→ 清除整个进程的 tgid 污点键；
 *   - 普通线程退出 → 清除自身 tid 键（fork 传播可能写入过）。
 *   修复旧版“任意线程退出即清除整个进程污点”的逃逸漏洞。
 */
SEC("tracepoint/sched/sched_process_exit")
int sentinel_cleanup_exit(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    __u32 key = (pid == tgid) ? tgid : pid;
    bpf_map_delete_elem(&taint_map, &key);
    return 0;
}

char _license[] SEC("license") = "GPL";
