/* SPDX-License-Identifier: GPL-1.0 WITH Linux-syscall-note */
#pragma once
#include <linux/ioctl.h>
#include <linux/types.h>

/* ===== ABI ===== */
#define KCLIP_ABI_VERSION        1
#define KCLIP_IOC_MAGIC          'U'
#define KCLIP_SLOT_DEFAULT       0
#define KCLIP_MIME_MAX           128
#define KCLIP_COMM_MAX           16

#ifndef __aligned_u64
# define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif

/* ===== flags ===== */
/* push */
#define KCLIP_PUSH_F_REQUIRE_SEALS   (1ULL << 0) /* producer must seal memfd */
#define KCLIP_PUSH_F_PRIVATE         (1ULL << 1) /* policy: same uid/ns only */

/* pull */
#define KCLIP_PULL_F_NONBLOCK        (1U << 0)
#define KCLIP_PULL_F_PEEK            (1U << 1)   /* default if neither set */
#define KCLIP_PULL_F_POP             (1U << 2)   /* destructive */
#define KCLIP_PULL_F_GET_PART_FDS    (1U << 3)   /* return per-part FDs */

/* part */
#define KCLIP_PART_F_PRIMARY         (1ULL << 0) /* preferred representation */

/* limits policy */
#define KCLIP_LIMITS_F_EVICT_LRU     (1U << 0)   /* drop oldest when full */
#define KCLIP_LIMITS_F_REJECT        (1U << 1)   /* reject new when full */

/* ===== types ===== */
struct uclip_mime {
    __u16 len;                     /* bytes valid in s[] (NUL optional) */
    __u16 _pad;
    char  s[KCLIP_MIME_MAX];
};

struct uclip_meta {
    __u64 ts_ns;                   /* monotonic-ish timestamp (doc in driver) */
    __u32 uid;
    __u32 pid;
    char  comm[KCLIP_COMM_MAX];    /* best-effort */
};

/* one data representation (e.g., text/plain, text/html, image/png) */
struct uclip_part {
    struct uclip_mime mime;
    __u64 size;
    __u64 flags;                   /* UCLIP_PART_F_* */
    __s32 memfd_fd;                /* PUSH: provided; PULL: kernel installs RO fd */
    __u32 _pad;
};

/* ===== ioctls ===== */
/* PUSH: publish one message with N parts (memfd-backed). */
struct uclip_push {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_push) */
    __u32 slot;
    __u32 parts_count;             /* # of elements at parts_ptr */
    __u64 flags;                   /* UCLIP_PUSH_F_* */
    __aligned_u64 parts_ptr;       /* userspace array of struct uclip_part */
};

/* PULL: peek/pop next message; optionally get per-part FDs. */
struct uclip_pull {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_pull) */
    __u32 slot;
    __u32 flags;                   /* UCLIP_PULL_F_* (PEEK default) */

    __u64 out_seqno;               /* 0 if empty */
    __u64 out_total_size;          /* sum of parts */
    __u32 out_parts_count;
    __u32 _pad0;

    struct uclip_meta out_meta;    /* writer metadata */

    __u32 out_parts_cap;           /* capacity of array at out_parts_ptr */
    __u32 _pad1;
    __aligned_u64 out_parts_ptr;   /* array for kernel to fill (struct uclip_part) */
};

/* ACK: after PEEK, explicitly drop message by seqno. */
struct uclip_ack {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_ack) */
    __u32 slot;
    __u32 _pad;
    __u64 seqno;
};

/* HEAD_INFO: cheap peek summary of current head (no FDs). */
struct uclip_head_info {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_head_info) */
    __u32 slot;
    __u32 _pad0;
    __u64 out_seqno;               /* 0 if empty */
    __u64 out_total_size;
    __u32 out_parts_count;
    __u32 _pad1;
    struct uclip_mime out_primary_mime;
    struct uclip_meta out_meta;
};

/* SLOT_LIST: enumerate slots with depth/bytes. */
struct uclip_slot_entry {
    __u32 slot_id;
    __u32 depth;                   /* messages waiting */
    __u64 bytes;                   /* approx total payload bytes */
};
struct uclip_slot_list {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_slot_list) */
    __u32 in_cap;                  /* capacity of entries[] */
    __u32 out_count;               /* kernel filled count */
    __aligned_u64 entries_ptr;     /* userspace array of uclip_slot_entry */
};

/* LIMITS_GET/SET: quotas & policy. */
struct uclip_limits {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_limits) */
    __u32 scope;                   /* 0=global, 1=per-slot (scope_id=slot) */
    __u32 scope_id;
    __u64 max_msg_bytes;           /* per-message cap */
    __u32 max_parts;               /* per-message */
    __u32 max_depth;               /* per-slot */
    __u64 max_bytes_total;         /* per-scope */
    __u32 policy_flags;            /* UCLIP_LIMITS_F_* */
    __u32 _pad;
};

/* STATS_GET: counters. */
struct uclip_stats {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_stats) */
    __u32 slot;                    /* 0=default or specific slot id */
    __u32 _pad;
    __u64 depth;                   /* current messages */
    __u64 bytes;                   /* current bytes */
    __u64 enqueued;                /* lifetime pushes */
    __u64 dequeued;                /* lifetime removes (ACK/POP) */
    __u64 dropped;                 /* rejects/evicts */
};

/* EVENTFD: register/unregister for empty→non-empty transitions. */
struct uclip_eventfd {
    __u16 abi_version;             /* = UCLIP_ABI_VERSION */
    __u16 struct_size;             /* = sizeof(struct uclip_eventfd) */
    __u32 slot;
    __u32 _pad;
    __s32 eventfd;                 /* >=0 to register; -1 to unregister */
    __u32 _pad2;
};

/* ===== numbers ===== */
#define UCLIP_IOC_PUSH          _IOW (UCLIP_IOC_MAGIC, 0x01, struct uclip_push)
#define UCLIP_IOC_PULL          _IOWR(UCLIP_IOC_MAGIC, 0x02, struct uclip_pull)
#define UCLIP_IOC_ACK           _IOW (UCLIP_IOC_MAGIC, 0x03, struct uclip_ack)
#define UCLIP_IOC_HEAD_INFO     _IOWR(UCLIP_IOC_MAGIC, 0x04, struct uclip_head_info)
#define UCLIP_IOC_SLOT_LIST     _IOWR(UCLIP_IOC_MAGIC, 0x05, struct uclip_slot_list)
#define UCLIP_IOC_LIMITS_GET    _IOWR(UCLIP_IOC_MAGIC, 0x06, struct uclip_limits)
#define UCLIP_IOC_LIMITS_SET    _IOW (UCLIP_IOC_MAGIC, 0x07, struct uclip_limits)
#define UCLIP_IOC_STATS_GET     _IOWR(UCLIP_IOC_MAGIC, 0x08, struct uclip_stats)
#define UCLIP_IOC_EVENTFD       _IOW (UCLIP_IOC_MAGIC, 0x09, struct uclip_eventfd)
/* 0x0A–0x1F reserved */

