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
/* publish */
#define KCLIP_PUBLISH_F_REQUIRE_SEALS   (1ULL << 0) /* producer must seal memfd */
#define KCLIP_PUBLISH_F_PRIVATE         (1ULL << 1) /* policy: same uid/ns only */

/* fetch */
#define KCLIP_FETCH_F_NONBLOCK          (1U << 0)
#define KCLIP_FETCH_F_PEEK              (1U << 1)   /* default if neither set */
#define KCLIP_FETCH_F_POP               (1U << 2)   /* destructive */
#define KCLIP_FETCH_F_GET_PART_FDS      (1U << 3)   /* return per-part FDs */

/* part */
#define KCLIP_PART_F_PRIMARY            (1ULL << 0) /* preferred representation */

/* limits policy */
#define KCLIP_LIMITS_F_EVICT_LRU        (1U << 0)   /* drop oldest when full */
#define KCLIP_LIMITS_F_REJECT           (1U << 1)   /* reject new when full */

/* ===== types ===== */
struct kclip_mime {
	__u16 len;                      /* bytes valid in s[] (NUL optional) */
	__u16 _pad;
	char  s[KCLIP_MIME_MAX];
};

struct kclip_meta {
	__u64 ts_ns;                    /* monotonic-ish timestamp */
	__u32 uid;
	__u32 pid;
	char  comm[KCLIP_COMM_MAX];     /* best-effort */
};

/* one data representation (e.g., text/plain, text/html, image/png) */
struct kclip_part {
	struct kclip_mime mime;
	__u64 size;
	__u64 flags;                    /* KCLIP_PART_F_* */
	__s32 memfd_fd;                 /* PUBLISH: provided; FETCH: kernel installs RO fd */
	__u32 _pad;
};

/* ===== ioctls ===== */
/* MSG_PUBLISH: publish one message with N parts (memfd-backed). */
struct kclip_msg_publish {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_msg_publish) */
	__u32 slot;
	__u32 parts_count;              /* # of elements at parts_ptr */
	__u64 flags;                    /* KCLIP_PUBLISH_F_* */
	__aligned_u64 parts_ptr;        /* userspace array of struct kclip_part */
};

/* MSG_FETCH: peek/pop next message; optionally get per-part FDs. */
struct kclip_msg_fetch {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_msg_fetch) */
	__u32 slot;
	__u32 flags;                    /* KCLIP_FETCH_F_* (PEEK default) */

	__u64 out_seqno;                /* 0 if empty */
	__u64 out_total_size;           /* sum of parts */
	__u32 out_parts_count;
	__u32 _pad0;

	struct kclip_meta out_meta;     /* writer metadata */

	__u32 out_parts_cap;            /* capacity of array at out_parts_ptr */
	__u32 _pad1;
	__aligned_u64 out_parts_ptr;    /* array for kernel to fill (struct kclip_part) */
};

/* MSG_ACK: after PEEK, explicitly drop message by seqno. */
struct kclip_msg_ack {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_msg_ack) */
	__u32 slot;
	__u32 _pad;
	__u64 seqno;
};

/* MSG_CONSUME: destructive remove; if seqno==0, consume head. */
struct kclip_msg_consume {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_msg_consume) */
	__u32 slot;
	__u32 _pad;
	__u64 seqno;                    /* 0 = consume head; else specific seqno */
};

/* HEAD: cheap peek summary of current head (no FDs). */
struct kclip_head {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_head) */
	__u32 slot;
	__u32 _pad0;
	__u64 out_seqno;                /* 0 if empty */
	__u64 out_total_size;
	__u32 out_parts_count;
	__u32 _pad1;
	struct kclip_mime out_primary_mime;
	struct kclip_meta out_meta;
};

/* SLOTS: enumerate slots with depth/bytes. */
struct kclip_slot_entry {
	__u32 slot_id;
	__u32 depth;                    /* messages waiting */
	__u64 bytes;                    /* approx total payload bytes */
};
struct kclip_slot_list {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_slot_list) */
	__u32 in_cap;                   /* capacity of entries[] */
	__u32 out_count;                /* kernel filled count */
	__aligned_u64 entries_ptr;      /* userspace array of kclip_slot_entry */
};

/* LIMITS_GET/SET: quotas & policy. */
struct kclip_limits {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_limits) */
	__u32 scope;                    /* 0=global, 1=per-slot (scope_id=slot) */
	__u32 scope_id;
	__u64 max_msg_bytes;            /* per-message cap */
	__u32 max_parts;                /* per-message */
	__u32 max_depth;                /* per-slot */
	__u64 max_bytes_total;          /* per-scope */
	__u32 policy_flags;             /* KCLIP_LIMITS_F_* */
	__u32 _pad;
};

/* STATS_GET: counters. */
struct kclip_stats {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_stats) */
	__u32 slot;                     /* 0=default or specific slot id */
	__u32 _pad;
	__u64 depth;                    /* current messages */
	__u64 bytes;                    /* current bytes */
	__u64 enqueued;                 /* lifetime publishes */
	__u64 dequeued;                 /* lifetime removes (ACK/CONSUME/POP) */
	__u64 dropped;                  /* rejects/evicts */
};

/* EVENTFD: register/unregister for empty→non-empty transitions. */
struct kclip_eventfd {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_eventfd) */
	__u32 slot;
	__u32 _pad;
	__s32 eventfd;                  /* >=0 to register; -1 to unregister */
	__u32 _pad2;
};

/* BIND_SLOT: bind this fd to a default slot (optional helper). */
struct kclip_bind_slot {
	__u16 abi_version;              /* = KCLIP_ABI_VERSION */
	__u16 struct_size;              /* = sizeof(struct kclip_bind_slot) */
	__u32 slot;
	__u32 _pad;
};

/* ===== numbers ===== */
#define KCLIP_IOC_MSG_PUBLISH   _IOW (KCLIP_IOC_MAGIC, 0x01, struct kclip_msg_publish)
#define KCLIP_IOC_MSG_FETCH     _IOWR(KCLIP_IOC_MAGIC, 0x02, struct kclip_msg_fetch)
#define KCLIP_IOC_MSG_ACK       _IOW (KCLIP_IOC_MAGIC, 0x03, struct kclip_msg_ack)
#define KCLIP_IOC_HEAD          _IOWR(KCLIP_IOC_MAGIC, 0x04, struct kclip_head)
#define KCLIP_IOC_SLOT_LIST     _IOWR(KCLIP_IOC_MAGIC, 0x05, struct kclip_slot_list)
#define KCLIP_IOC_LIMITS_GET    _IOWR(KCLIP_IOC_MAGIC, 0x06, struct kclip_limits)
#define KCLIP_IOC_LIMITS_SET    _IOW (KCLIP_IOC_MAGIC, 0x07, struct kclip_limits)
#define KCLIP_IOC_STATS_GET     _IOWR(KCLIP_IOC_MAGIC, 0x08, struct kclip_stats)
#define KCLIP_IOC_EVENTFD       _IOW (KCLIP_IOC_MAGIC, 0x09, struct kclip_eventfd)
#define KCLIP_IOC_BIND_SLOT     _IOW (KCLIP_IOC_MAGIC, 0x0A, struct kclip_bind_slot)
#define KCLIP_IOC_MSG_CONSUME   _IOW (KCLIP_IOC_MAGIC, 0x0B, struct kclip_msg_consume)
/* 0x0C–0x1F reserved */

