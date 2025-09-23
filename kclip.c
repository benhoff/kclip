// SPDX-License-Identifier: GPL-2.0
// kclip.c — minimal misc device for a clipboard-like driver

#include <linux/cred.h>
#include <linux/eventfd.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>
#include <linux/shmem_fs.h>  /* shmem_mapping() */
#include <uapi/linux/fcntl.h> /* F_SEAL_* bits for documentation */



#include "include/uapi/kclip_uapi.h"

#define KCLIP_DEFAULT_MAX_MSG_BYTES    (16ULL * 1024 * 1024)   /* 16 MiB */
#define KCLIP_DEFAULT_MAX_PARTS        16
#define KCLIP_DEFAULT_MAX_DEPTH        128
#define KCLIP_DEFAULT_MAX_BYTES_TOTAL  (128ULL * 1024 * 1024)  /* 128 MiB */
#define KCLIP_DEFAULT_POLICY_FLAGS     UCLIP_LIMITS_F_EVICT_LRU
#define KCLIP_IOC_BIND_SLOT _IOW('K', 0x30, struct uclip_bind_slot)

#define KCLIP_ABI_CHECK(_dst, _userp, _type)                                \
	do {                                                                    \
		if (copy_from_user(&(_dst), (void __user *)(_userp), sizeof(_dst))) \
			return -EFAULT;                                                 \
		if ((_dst).abi_version != UCLIP_ABI_VERSION)                        \
			return -EPROTO;                                                 \
		if ((_dst).struct_size != sizeof(_type))                            \
			return -EINVAL;                                                 \
	} while (0)

struct uclip_bind_slot {
	__u32 abi_version;
	__u32 struct_size;
	__u32 slot; /* 0..KCLIP_SLOTS_PER_USER-1 */
	__u32 _pad;
};

/* One in-kernel part (kernel view of a UAPI kclip_part) */
struct kclip_part_k {
	/* immutable after enqueue */
	struct file   *memfd;      /* get_file() at push; fput() at free */
	u64            size;       /* bytes valid */
	u64            flags;      /* UCLIP_PART_F_* */
	struct kclip_mime mime;    /* copied from user, len-authoritative */
	/* optional: u64 off; // if using a shared memfd for multiple parts */
};

/* One message sitting in a slot FIFO */
struct kclip_msg {
	struct list_head node;     /* linked into kclip_slot.q (FIFO) */

	/* immutable after enqueue */
	u64            seqno;      /* unique within slot (monotonic) */
	u64            total_size; /* sum(parts[i].size) */
	u32            parts_count;
	struct kclip_meta meta;    /* ts_ns/uid/pid/comm snapshot at push */

	/* flexible array of parts, allocated with the message */
	struct kclip_part_k parts[]; /* parts_count elements */

	/* future: policy bits, provenance, checksum, etc. */
};

/* Per-slot queue, quotas, and notifications */
struct kclip_slot {
	/* protects q, counters, and efd_armed */
	spinlock_t       lock;
	struct list_head q;            /* FIFO of kclip_msg */
	wait_queue_head_t wq;          /* waiters for non-empty */
	struct eventfd_ctx *efd;       /* optional empty->non-empty notifier */
	bool             efd_armed;    /* true when depth==0 and notif is armed */

	/* current state (under lock) */
	u64              next_seq;     /* next seq to assign */
	u32              depth;        /* #messages in q */
	u64              bytes;        /* approx total payload bytes in q */

	/* limits/policy (write rarely; read under lock) */
	u64 max_msg_bytes;             /* per-message cap */
	u32 max_parts;                 /* per-message cap */
	u32 max_depth;                 /* per-slot cap (messages) */
	u64 max_bytes_total;           /* per-slot cap (bytes) */
	u32 policy_flags;              /* UCLIP_LIMITS_F_* */
};

/* Lifetime counters per slot (ever) */
struct kclip_counters {
	u64 enq;       /* pushes accepted */
	u64 deq;       /* removes (ACK/POP) */
	u64 dropped;   /* rejects/evictions */
};

/* Per-user clipboard: 10 slots per user */
#define KCLIP_SLOTS_PER_USER 10
struct kclip_user {
	struct kref     ref;           /* get/put */
	struct rcu_head rcu;           /* kfree_rcu() path */
	kuid_t          kuid;          /* key in g_users (ns-aware) */

	struct kclip_slot    slots[KCLIP_SLOTS_PER_USER];
	struct kclip_counters ctrs [KCLIP_SLOTS_PER_USER];
};

/* Global registry: kuid -> kclip_user */
static DEFINE_MUTEX(g_users_lock);                 /* serialize create/remove */
static DEFINE_XARRAY_FLAGS(g_users, XA_FLAGS_LOCK_IRQ); /* RCU-friendly map */

/* Device singleton now only carries miscdev (no global queue) */
struct kclip_dev {
	struct miscdevice mdev;
};

static inline void kclip_slot_init(struct kclip_slot *s)
{
	spin_lock_init(&s->lock);
	INIT_LIST_HEAD(&s->q);
	init_waitqueue_head(&s->wq);
	s->efd       = NULL;
	s->efd_armed = true; /* arm first empty->non-empty edge */

	s->next_seq  = 1;
	s->depth     = 0;
	s->bytes     = 0;

	s->max_msg_bytes   = KCLIP_DEFAULT_MAX_MSG_BYTES;
	s->max_parts       = KCLIP_DEFAULT_MAX_PARTS;
	s->max_depth       = KCLIP_DEFAULT_MAX_DEPTH;
	s->max_bytes_total = KCLIP_DEFAULT_MAX_BYTES_TOTAL;
	s->policy_flags    = KCLIP_DEFAULT_POLICY_FLAGS;
}

/* Drain queue and release eventfd if present.
 * NOTE: Do NOT call with s->lock held. We take it internally. */
static inline void kclip_slot_fini(struct kclip_slot *s)
{
	unsigned long flags;

	/* Drain FIFO (safe even if already empty). */
	spin_lock_irqsave(&s->lock, flags);
	while (!list_empty(&s->q)) {
		struct kclip_msg *m = list_first_entry(&s->q, struct kclip_msg, node);
		list_del(&m->node);
		spin_unlock_irqrestore(&s->lock, flags);

		/* Free message (and future: fput() each m->parts[i].memfd). */
		kclip_msg_free(m);

		spin_lock_irqsave(&s->lock, flags);
	}
	spin_unlock_irqrestore(&s->lock, flags);

	if (s->efd) {
		eventfd_ctx_put(s->efd);
		s->efd = NULL;
	}
}

/* =========================
 * Message alloc / free
 * ========================= */

/* Allocate a message with room for `parts_count` parts.
 * Fields are zeroed; you fill them before enqueue. */
static inline struct kclip_msg *
kclip_msg_alloc(u32 parts_count, gfp_t gfp)
{
	size_t sz_hdr = sizeof(struct kclip_msg);
	size_t sz_parts = (size_t)parts_count * sizeof(struct kclip_part_k);
	struct kclip_msg *m;

	/* guard against overflow */
	if (parts_count > U32_MAX / sizeof(struct kclip_part_k))
		return NULL;

	m = kzalloc(sz_hdr + sz_parts, gfp);
	if (!m)
		return NULL;

	INIT_LIST_HEAD(&m->node);
	m->parts_count = parts_count;
	/* seqno/total_size/meta filled by caller */
	return m;
}

/* Free a message. If parts hold memfd files, drop them.
 * Call WITHOUT holding the slot spinlock. */
static inline void kclip_msg_free(struct kclip_msg *m)
{
	u32 i;

	if (!m)
		return;

	for (i = 0; i < m->parts_count; i++) {
		struct kclip_part_k *p = &m->parts[i];
		if (p->memfd) {
			fput(p->memfd);
			p->memfd = NULL;
		}
	}
	kfree(m);
}

/* =========================
 * User alloc / lookup / put
 * ========================= */

/* Allocate and initialize a fresh per-user clipboard object. */
static inline struct kclip_user *
kclip_user_alloc(kuid_t kuid)
{
	int i;
	struct kclip_user *u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return NULL;

	kref_init(&u->ref);
	u->kuid = kuid;
	for (i = 0; i < KCLIP_SLOTS_PER_USER; i++) {
		kclip_slot_init(&u->slots[i]);
		u->ctrs[i].enq = 0;
		u->ctrs[i].deq = 0;
		u->ctrs[i].dropped = 0;
	}
	return u;
}

static inline void kclip_user_release(struct kref *kref)
{
	int i;
	struct kclip_user *u = container_of(kref, struct kclip_user, ref);

	/* finish slots (drain + put eventfd) */
	for (i = 0; i < KCLIP_SLOTS_PER_USER; i++)
		kclip_slot_fini(&u->slots[i]);

	kfree_rcu(u, rcu);
}

static inline void kclip_user_get(struct kclip_user *u)
{
	kref_get(&u->ref);
}

static inline void kclip_user_put(struct kclip_user *u)
{
	kref_put(&u->ref, kclip_user_release);
}

/* RCU read-side lookup by kuid; returns with ref taken or NULL. */
static inline struct kclip_user *
kclip_user_lookup_rcu(kuid_t kuid)
{
	struct kclip_user *u;

	rcu_read_lock();
	u = xa_load(&g_users, __kuid_val(kuid));
	if (u)
		kclip_user_get(u);
	rcu_read_unlock();
	return u;
}

/* Get existing or create new per-user object. */
static inline struct kclip_user *
kclip_user_get_or_create_current(void)
{
	kuid_t kuid = current_fsuid();
	struct kclip_user *u = kclip_user_lookup_rcu(kuid);

	if (u)
		return u;

	/* Slow path: create under mutex, handle races. */
	u = kclip_user_alloc(kuid);
	if (!u)
		return NULL;

	mutex_lock(&g_users_lock);
	{
		struct kclip_user *exist = xa_load(&g_users, __kuid_val(kuid));
		if (exist) {
			kclip_user_get(exist);
			mutex_unlock(&g_users_lock);
			/* drop our new one */
			kclip_user_put(u); /* releases and frees */
			return exist;
		}
		if (xa_err(xa_store(&g_users, __kuid_val(kuid), u, GFP_KERNEL))) {
			mutex_unlock(&g_users_lock);
			kclip_user_put(u);
			return NULL;
		}
	}
	kclip_user_get(u);
	mutex_unlock(&g_users_lock);
	return u;
}

/* Optional: remove a user from registry (admin/unload). Caller ensures quiescence. */
static inline void kclip_user_erase(kuid_t kuid)
{
	struct kclip_user *u;

	mutex_lock(&g_users_lock);
	u = xa_erase(&g_users, __kuid_val(kuid));
	mutex_unlock(&g_users_lock);

	if (u)
		kclip_user_put(u); /* drop our ref; may free via RCU */
}

/* =========================
 * Slot id check helper
 * ========================= */

static inline int kclip_slot_index(u32 slot_id)
{
	return (slot_id < KCLIP_SLOTS_PER_USER) ? (int)slot_id : -EINVAL;
}


static inline bool slot_empty(struct kclip_slot *s)
{
	return list_empty(&s->q);
}

/* ===== file operations ===== */
static int kclip_open(struct inode *ino, struct file *filp)
{
	struct kclip_fctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->u = kclip_user_get_or_create_current();
	if (!ctx->u) {
		kfree(ctx);
		return -ENOMEM;
	}
	ctx->slot = 0; /* default; can be changed via ioctl later */

	filp->private_data = ctx;
	return 0;
}

static int kclip_release(struct inode *ino, struct file *filp)
{
	struct kclip_fctx *ctx = filp->private_data;
	if (ctx) {
		if (ctx->u)
			kclip_user_put(ctx->u);
		kfree(ctx);
		filp->private_data = NULL;
	}
	return 0;
}

/* poll/epoll: readable when *this user's bound slot* has a message */
static __poll_t kclip_poll(struct file *filp, poll_table *wait)
{
	struct kclip_fctx *ctx = filp->private_data;
	struct kclip_slot *s;
	unsigned long flags;
	__poll_t mask = 0;
	u32 depth;
	u64 bytes;

	if (!ctx || !ctx->u)
		return EPOLLERR;

	/* per-user, per-slot */
	if (ctx->slot >= KCLIP_SLOTS_PER_USER)
		return EPOLLERR;

	s = &ctx->u->slots[ctx->slot];

	poll_wait(filp, &s->wq, wait);

	/* snapshot under lock */
	spin_lock_irqsave(&s->lock, flags);
	depth = s->depth;
	bytes = s->bytes;
	spin_unlock_irqrestore(&s->lock, flags);

	if (depth > 0)
		mask |= EPOLLIN;

	/* Optional: indicate writers likely allowed under limits */
	if (depth < s->max_depth && bytes < s->max_bytes_total)
		mask |= EPOLLOUT;

	return mask;
}


static inline int kclip_get_slot_for_current_user(u32 slot_id,
						  struct kclip_user **out_u,
						  struct kclip_slot **out_s,
						  struct kclip_counters **out_ctr)
{
	int idx;
	struct kclip_user *u = kclip_user_get_or_create_current();
	if (!u)
		return -ENOMEM;

	idx = kclip_slot_index(slot_id);
	if (idx < 0) {
		kclip_user_put(u);
		return idx;
	}

	*out_s = &u->slots[idx];
	*out_ctr = &u->ctrs[idx];
	*out_u = u;
	return 0;
}

/* Pick a "primary" MIME for head_info: prefer PART_F_PRIMARY; else first part. */
static inline void kclip_pick_primary_mime(struct kclip_msg *m, struct uclip_mime *out)
{
	u32 i;

	memset(out, 0, sizeof(*out));
	if (!m || m->parts_count == 0)
		return;

	for (i = 0; i < m->parts_count; i++) {
		if (m->parts[i].flags & UCLIP_PART_F_PRIMARY) {
			*out = m->parts[i].mime;
			return;
		}
	}
	*out = m->parts[0].mime;
}

static long kclip_ioc_head(unsigned long arg)
{
	struct uclip_head_info inout;
	struct kclip_user *u = NULL;
	struct kclip_slot *s = NULL;
	struct kclip_counters *ctr = NULL;
	unsigned long flags;
	struct kclip_msg *m = NULL;
	int ret;

	KCLIP_ABI_CHECK(inout, arg, struct uclip_head_info);

	ret = kclip_get_slot_for_current_user(inout.slot, &u, &s, &ctr);
	if (ret)
		return ret;

	/* Fill defaults (empty case) */
	inout.out_seqno       = 0;
	inout.out_total_size  = 0;
	inout.out_parts_count = 0;
	memset(&inout.out_meta, 0, sizeof(inout.out_meta));
	memset(&inout.out_primary_mime, 0, sizeof(inout.out_primary_mime));

	spin_lock_irqsave(&s->lock, flags);
	if (!list_empty(&s->q)) {
		m = list_first_entry(&s->q, struct kclip_msg, node);
		inout.out_seqno       = m->seqno;
		inout.out_total_size  = m->total_size;
		inout.out_parts_count = m->parts_count;
		inout.out_meta        = m->meta;
		kclip_pick_primary_mime(m, &inout.out_primary_mime);
	}
	spin_unlock_irqrestore(&s->lock, flags);

	kclip_user_put(u);

	if (copy_to_user((void __user *)arg, &inout, sizeof(inout)))
		return -EFAULT;
	return 0;
}

static long kclip_ioc_slot_list(unsigned long arg)
{
	struct uclip_slot_list hdr;
	struct kclip_user *u = NULL;
	u32 i, to_fill;

	KCLIP_ABI_CHECK(hdr, arg, struct uclip_slot_list);

	/* We ignore hdr.in_cap==0 gracefully (no entries returned). */
	if (hdr.in_cap > KCLIP_SLOTS_PER_USER)
		hdr.in_cap = KCLIP_SLOTS_PER_USER;

	/* Early write-back of out_count=0 in case of early returns */
	hdr.out_count = 0;

	if (copy_to_user((void __user *)arg, &hdr, sizeof(hdr)))
		return -EFAULT;

	u = kclip_user_get_or_create_current();
	if (!u)
		return -ENOMEM;

	to_fill = hdr.in_cap;
	for (i = 0; i < to_fill; i++) {
		struct uclip_slot_entry ent;
		struct kclip_slot *s = &u->slots[i];
		unsigned long flags;

		ent.slot_id = i;

		spin_lock_irqsave(&s->lock, flags);
		ent.depth = s->depth;
		ent.bytes = s->bytes;
		spin_unlock_irqrestore(&s->lock, flags);

		if (copy_to_user((void __user *)(uintptr_t)hdr.entries_ptr
				          + i * sizeof(ent),
				 &ent, sizeof(ent))) {
			kclip_user_put(u);
			return -EFAULT;
		}
	}

	/* Update out_count */
	hdr.out_count = to_fill;
	if (copy_to_user((void __user *)arg, &hdr, sizeof(hdr))) {
		kclip_user_put(u);
		return -EFAULT;
	}

	kclip_user_put(u);
	return 0;
}

static long kclip_ioc_limits_get(unsigned long arg)
{
	struct uclip_limits lim;
	struct kclip_user *u = NULL;
	struct kclip_slot *s = NULL;
	struct kclip_counters *ctr = NULL;
	unsigned long flags;
	int ret;

	KCLIP_ABI_CHECK(lim, arg, struct uclip_limits);

	if (lim.scope == 0) /* global */
		return -EOPNOTSUPP;

	if (lim.scope != 1)
		return -EINVAL;

	ret = kclip_get_slot_for_current_user(lim.scope_id, &u, &s, &ctr);
	if (ret)
		return ret;

	spin_lock_irqsave(&s->lock, flags);
	lim.max_msg_bytes   = s->max_msg_bytes;
	lim.max_parts       = s->max_parts;
	lim.max_depth       = s->max_depth;
	lim.max_bytes_total = s->max_bytes_total;
	lim.policy_flags    = s->policy_flags;
	spin_unlock_irqrestore(&s->lock, flags);

	kclip_user_put(u);

	if (copy_to_user((void __user *)arg, &lim, sizeof(lim)))
		return -EFAULT;
	return 0;
}

static long kclip_ioc_limits_set(unsigned long arg)
{
	struct uclip_limits lim;
	struct kclip_user *u = NULL;
	struct kclip_slot *s = NULL;
	struct kclip_counters *ctr = NULL;
	unsigned long flags;
	int ret;

	KCLIP_ABI_CHECK(lim, arg, struct uclip_limits);

	if (lim.scope == 0) /* global */
		return -EOPNOTSUPP;

	if (lim.scope != 1)
		return -EINVAL;

	/* Basic sanity */
	if (lim.max_parts == 0 ||
	    lim.max_depth == 0 ||
	    lim.max_msg_bytes == 0 ||
	    lim.max_bytes_total == 0)
		return -EINVAL;

	ret = kclip_get_slot_for_current_user(lim.scope_id, &u, &s, &ctr);
	if (ret)
		return ret;

	spin_lock_irqsave(&s->lock, flags);
	s->max_msg_bytes   = lim.max_msg_bytes;
	s->max_parts       = lim.max_parts;
	s->max_depth       = lim.max_depth;
	s->max_bytes_total = lim.max_bytes_total;
	s->policy_flags    = lim.policy_flags;
	spin_unlock_irqrestore(&s->lock, flags);

	kclip_user_put(u);
	return 0;
}

static long kclip_ioc_stats_get(unsigned long arg)
{
	struct uclip_stats st;
	struct kclip_user *u = NULL;
	struct kclip_slot *s = NULL;
	struct kclip_counters *ctr = NULL;
	unsigned long flags;
	int ret;

	KCLIP_ABI_CHECK(st, arg, struct uclip_stats);

	ret = kclip_get_slot_for_current_user(st.slot, &u, &s, &ctr);
	if (ret)
		return ret;

	spin_lock_irqsave(&s->lock, flags);
	st.depth   = s->depth;
	st.bytes   = s->bytes;
	/* lifetime counters live beside slot; update under same lock to snapshot consistently */
	st.enqueued = ctr->enq;
	st.dequeued = ctr->deq;
	st.dropped  = ctr->dropped;
	spin_unlock_irqrestore(&s->lock, flags);

	kclip_user_put(u);

	if (copy_to_user((void __user *)arg, &st, sizeof(st)))
		return -EFAULT;
	return 0;
}

static long kclip_ioc_eventfd(unsigned long arg)
{
	struct uclip_eventfd ev;
	struct kclip_user *u = NULL;
	struct kclip_slot *s = NULL;
	struct kclip_counters *ctr = NULL;
	unsigned long flags;
	int ret;

	KCLIP_ABI_CHECK(ev, arg, struct uclip_eventfd);

	ret = kclip_get_slot_for_current_user(ev.slot, &u, &s, &ctr);
	if (ret)
		return ret;

	if (ev.eventfd >= 0) {
		struct eventfd_ctx *newctx = eventfd_ctx_fdget(ev.eventfd);
		if (IS_ERR(newctx)) {
			kclip_user_put(u);
			return PTR_ERR(newctx);
		}

		spin_lock_irqsave(&s->lock, flags);
		if (s->efd)
			eventfd_ctx_put(s->efd);
		s->efd = newctx;
		/* (Re)arm edge: only fire on next empty->non-empty transition */
		s->efd_armed = (s->depth == 0);
		spin_unlock_irqrestore(&s->lock, flags);
	} else if (ev.eventfd == -1) {
		spin_lock_irqsave(&s->lock, flags);
		if (s->efd) {
			struct eventfd_ctx *old = s->efd;
			s->efd = NULL;
			spin_unlock_irqrestore(&s->lock, flags);
			eventfd_ctx_put(old);
		} else {
			spin_unlock_irqrestore(&s->lock, flags);
		}
	} else {
		kclip_user_put(u);
		return -EINVAL;
	}

	kclip_user_put(u);
	return 0;
}

static long kclip_ioc_bind_slot(struct file *filp, unsigned long arg)
{
	struct uclip_bind_slot bs;

	KCLIP_ABI_CHECK(bs, arg, struct uclip_bind_slot);
	if (bs.slot >= KCLIP_SLOTS_PER_USER)
		return -EINVAL;

	if (!filp->private_data)
		return -EINVAL;

	((struct kclip_fctx *)filp->private_data)->slot = bs.slot;
	return 0;
}

/* ==== helpers =========================================================== */

static inline void kclip_signal_nonempty(struct kclip_slot *s)
{
	/* eventfd fires only on empty->non-empty edge */
	if (s->efd && s->efd_armed && s->depth > 0) {
		eventfd_signal(s->efd, 1);
		s->efd_armed = false;
	}
	/* epoll waiters */
	wake_up_interruptible(&s->wq);
}

static inline void kclip_maybe_rearm_empty_edge(struct kclip_slot *s)
{
	if (s->depth == 0)
		s->efd_armed = true;
}

/* Remove and free a message from a slot (assumes not referenced elsewhere).
 * Caller must hold s->lock. */
static inline void kclip_remove_msg_locked(struct kclip_slot *s,
					   struct kclip_counters *ctr,
					   struct kclip_msg *m)
{
	list_del(&m->node);
	s->depth--;
	if (s->bytes >= m->total_size)
		s->bytes -= m->total_size;
	else
		s->bytes = 0;
	ctr->deq++;
	spin_unlock(&s->lock);
	kclip_msg_free(m);
	spin_lock(&s->lock);
}

/* Try to evict oldest until the new message would fit under policy.
 * Caller holds s->lock. Returns 0 if fits (maybe after evictions), -ENOSPC if reject. */
static int kclip_apply_admission_locked(struct kclip_slot *s,
					struct kclip_counters *ctr,
					u64 add_bytes)
{
	bool over_depth  = (s->depth + 1 > s->max_depth);
	bool over_bytes  = (s->bytes + add_bytes > s->max_bytes_total);
	if (!over_depth && !over_bytes)
		return 0;

	if (!(s->policy_flags & KCLIP_LIMITS_F_EVICT_LRU))
		return -ENOSPC;

	while ((s->depth + 1 > s->max_depth) ||
	       (s->bytes + add_bytes > s->max_bytes_total)) {
		if (list_empty(&s->q))
			break;
		/* evict oldest (head) */
		struct kclip_msg *old =
			list_first_entry(&s->q, struct kclip_msg, node);
		ctr->dropped++;
		kclip_remove_msg_locked(s, ctr, old);
	}
	return ((s->depth + 1 > s->max_depth) ||
		(s->bytes + add_bytes > s->max_bytes_total)) ? -ENOSPC : 0;
}

/* Install RO-ish FDs for parts; we can’t change open mode, so we dup the file.
 * On success, out_fds[i] contains fd numbers to return to user. On error,
 * all already-installed fds are put back. */
static int kclip_install_part_fds(struct kclip_msg *m, int *out_fds)
{
	u32 i;
	for (i = 0; i < m->parts_count; i++) {
		int fd = get_unused_fd_flags(O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			goto err;
		get_file(m->parts[i].memfd);      /* bump ref for fd_install */
		fd_install(fd, m->parts[i].memfd);
		out_fds[i] = fd;
	}
	return 0;
err:
	while (i--)
		close_fd(out_fds[i]);
	return -EMFILE;
}

static int kclip_build_msg_from_user(struct kclip_slot *s,
				     const struct kclip_msg_publish *pub,
				     struct kclip_msg **out)
{
	int ret = 0;
	u32 i;
	u64 total = 0;
	struct kclip_msg *m = NULL;
	struct kclip_part __user *uparts;
	size_t uparts_sz;

	if (pub->parts_count == 0 || pub->parts_count > s->max_parts)
		return -EINVAL;

	m = kclip_msg_alloc(pub->parts_count, GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	uparts = (struct kclip_part __user *)(uintptr_t)pub->parts_ptr;
	uparts_sz = sizeof(struct kclip_part);

	for (i = 0; i < pub->parts_count; i++) {
		struct kclip_part up;
		struct fd f;

		if (copy_from_user(&up, uparts + i, uparts_sz)) {
			ret = -EFAULT;
			goto fail;
		}
		/* size/mime sanity */
		if (!up.size || up.size > s->max_msg_bytes) { ret = -EINVAL; goto fail; }
		if (up.mime.len > KCLIP_MIME_MAX)            { ret = -EINVAL; goto fail; }

		if (check_add_overflow(total, up.size, &total)) { ret = -E2BIG; goto fail; }
		if (total > s->max_msg_bytes)                  { ret = -E2BIG; goto fail; }

		f = fdget(up.memfd_fd);
		if (!f.file) { ret = -EBADF; goto fail; }

		/* NEW: require memfd/shmem, and enforce seals if requested */
		ret = kclip_check_memfd_and_seals(f.file,
			!!(pub->flags & KCLIP_PUBLISH_F_REQUIRE_SEALS));
		if (ret) {
			fdput(f);
			goto fail;
		}

		/* Accept the file: hold our own ref; record metadata */
		m->parts[i].memfd = get_file(f.file);
		m->parts[i].size  = up.size;
		m->parts[i].flags = up.flags;
		m->parts[i].mime.len = up.mime.len;
		if (up.mime.len)
			memcpy(m->parts[i].mime.s, up.mime.s, up.mime.len);

		fdput(f);
	}

	m->total_size   = total;
	m->meta.ts_ns   = ktime_get_ns();
	m->meta.uid     = from_kuid_munged(&init_user_ns, current_fsuid());
	m->meta.pid     = task_pid_nr(current);
	strscpy(m->meta.comm, current->comm, sizeof(m->meta.comm));

	*out = m;
	return 0;

fail:
	kclip_msg_free(m);
	return ret;
}

static inline int kclip_check_memfd_and_seals(struct file *file, bool require_seals)
{
	/* Must be tmpfs/shmem (memfd uses shmem internally). */
	if (!file || !file->f_mapping || !shmem_mapping(file->f_mapping))
		return -EINVAL;

	if (!require_seals)
		return 0;
}

static long kclip_ioc_msg_publish(struct file *filp, unsigned long arg)
{
	struct kclip_fctx *ctx = filp->private_data;
	struct kclip_msg_publish pub;
	struct kclip_slot *s;
	struct kclip_counters *ctr;
	struct kclip_msg *m = NULL;
	unsigned long flags;
	int ret;

	KCLIP_ABI_CHECK(pub, arg, struct kclip_msg_publish);
	if (!ctx || !ctx->u) return -EINVAL;

	if (pub.slot >= KCLIP_SLOTS_PER_USER) return -EINVAL;
	s   = &ctx->u->slots[pub.slot];
	ctr = &ctx->u->ctrs[pub.slot];

	/* per-message caps */
	if (pub.parts_count == 0) return -EINVAL;

	ret = kclip_build_msg_from_user(s, &pub, &m);
	if (ret) return ret;

	/* admission + enqueue */
	spin_lock_irqsave(&s->lock, flags);
	ret = kclip_apply_admission_locked(s, ctr, m->total_size);
	if (ret) {
		ctr->dropped++;
		spin_unlock_irqrestore(&s->lock, flags);
		kclip_msg_free(m);
		return -ENOSPC;
	}
	m->seqno = s->next_seq++;
	list_add_tail(&m->node, &s->q);
	s->depth++;
	s->bytes += m->total_size;

	/* if queue was empty before, s->depth went from 0->1 */
	if (s->depth == 1) {
		/* depth already incremented; we want the edge behaviour */
		s->efd_armed = s->efd_armed; /* no-op, signal helper uses depth */
	}
	spin_unlock_irqrestore(&s->lock, flags);

	kclip_signal_nonempty(s);
	ctr->enq++;
	return 0;
}

static long kclip_ioc_msg_fetch(struct file *filp, unsigned long arg)
{
	struct kclip_fctx *ctx = filp->private_data;
	struct kclip_msg_fetch f;
	struct kclip_slot *s;
	struct kclip_counters *ctr; /* only for consistency snapshot; not modified */
	unsigned long flags;
	int ret = 0;
	bool want_pop, want_fds, nonblock;
	struct kclip_msg *m = NULL;

	KCLIP_ABI_CHECK(f, arg, struct kclip_msg_fetch);
	if (!ctx || !ctx->u) return -EINVAL;
	if (f.slot >= KCLIP_SLOTS_PER_USER) return -EINVAL;

	s   = &ctx->u->slots[f.slot];
	ctr = &ctx->u->ctrs[f.slot];

	want_pop  = !!(f.flags & KCLIP_FETCH_F_POP);
	want_fds  = !!(f.flags & KCLIP_FETCH_F_GET_PART_FDS);
	nonblock  = !!(f.flags & KCLIP_FETCH_F_NONBLOCK);

	/* wait if empty */
	if (!nonblock) {
		/* classic wait until depth>0 or signal */
		int wret = wait_event_interruptible(s->wq, READ_ONCE(s->depth) > 0);
		if (wret)
			return wret;
	}

	spin_lock_irqsave(&s->lock, flags);
	if (list_empty(&s->q)) {
		spin_unlock_irqrestore(&s->lock, flags);
		return -EAGAIN;
	}

	m = list_first_entry(&s->q, struct kclip_msg, node);

	/* Fill fetch summary */
	f.out_seqno       = m->seqno;
	f.out_total_size  = m->total_size;
	f.out_parts_count = m->parts_count;
	f.out_meta        = m->meta;
	spin_unlock_irqrestore(&s->lock, flags);

	/* If caller provided a parts buffer, fill it (mime/size/flags).
	 * If GET_PART_FDS set, also install FDs and write back numbers. */
	if (f.out_parts_cap > 0 && f.out_parts_ptr) {
		u32 i, n = min(f.out_parts_cap, m->parts_count);
		struct kclip_part part_tmp;
		u8 __user *base = (u8 __user *)(uintptr_t)f.out_parts_ptr;
		size_t sz = sizeof(struct kclip_part);
		int *fds = NULL;

		if (want_fds) {
			fds = kcalloc(n, sizeof(int), GFP_KERNEL);
			if (!fds)
				return -ENOMEM;
			ret = kclip_install_part_fds(m, fds);
			if (ret) {
				kfree(fds);
				return ret;
			}
		}

		for (i = 0; i < n; i++) {
			memset(&part_tmp, 0, sizeof(part_tmp));
			part_tmp.mime = m->parts[i].mime;
			part_tmp.size = m->parts[i].size;
			part_tmp.flags = m->parts[i].flags;
			part_tmp.memfd_fd = want_fds ? fds[i] : -1;
			if (copy_to_user(base + i * sz, &part_tmp, sz)) {
				/* best-effort cleanup of newly created fds */
				if (want_fds) {
					u32 j;
					for (j = 0; j < n; j++)
						if (fds[j] >= 0) close_fd(fds[j]);
				}
				kfree(fds);
				return -EFAULT;
			}
		}
		kfree(fds);
	}

	/* If POP, remove it now. Otherwise, leave it for ACK/CONSUME. */
	if (want_pop) {
		spin_lock_irqsave(&s->lock, flags);
		kclip_remove_msg_locked(s, ctr, m);
		kclip_maybe_rearm_empty_edge(s);
		spin_unlock_irqrestore(&s->lock, flags);
	}

	/* write back the header with outputs */
	if (copy_to_user((void __user *)arg, &f, sizeof(f)))
		return -EFAULT;

	return 0;
}

static long kclip_ioc_msg_ack(struct file *filp, unsigned long arg)
{
	struct kclip_fctx *ctx = filp->private_data;
	struct kclip_msg_ack a;
	struct kclip_slot *s;
	struct kclip_counters *ctr;
	unsigned long flags;
	struct kclip_msg *m;
	int found = 0;

	KCLIP_ABI_CHECK(a, arg, struct kclip_msg_ack);
	if (!ctx || !ctx->u) return -EINVAL;
	if (a.slot >= KCLIP_SLOTS_PER_USER) return -EINVAL;

	s   = &ctx->u->slots[a.slot];
	ctr = &ctx->u->ctrs[a.slot];

	spin_lock_irqsave(&s->lock, flags);
	list_for_each_entry(m, &s->q, node) {
		if (m->seqno == a.seqno) {
			kclip_remove_msg_locked(s, ctr, m);
			found = 1;
			break;
		}
	}
	kclip_maybe_rearm_empty_edge(s);
	spin_unlock_irqrestore(&s->lock, flags);

	return found ? 0 : -ENOENT;
}

static long kclip_ioc_msg_consume(struct file *filp, unsigned long arg)
{
	struct kclip_fctx *ctx = filp->private_data;
	struct kclip_msg_consume c;
	struct kclip_slot *s;
	struct kclip_counters *ctr;
	unsigned long flags;
	struct kclip_msg *m;
	int found = 0;

	KCLIP_ABI_CHECK(c, arg, struct kclip_msg_consume);
	if (!ctx || !ctx->u) return -EINVAL;
	if (c.slot >= KCLIP_SLOTS_PER_USER) return -EINVAL;

	s   = &ctx->u->slots[c.slot];
	ctr = &ctx->u->ctrs[c.slot];

	spin_lock_irqsave(&s->lock, flags);
	if (c.seqno == 0) {
		if (!list_empty(&s->q)) {
			m = list_first_entry(&s->q, struct kclip_msg, node);
			kclip_remove_msg_locked(s, ctr, m);
			found = 1;
		}
	} else {
		list_for_each_entry(m, &s->q, node) {
			if (m->seqno == c.seqno) {
				kclip_remove_msg_locked(s, ctr, m);
				found = 1;
				break;
			}
		}
	}
	kclip_maybe_rearm_empty_edge(s);
	spin_unlock_irqrestore(&s->lock, flags);

	return found ? 0 : -ENOENT;
}


/* unified ioctl entry — all operations are stubs for now */
static long kclip_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case KCLIP_IOC_MSG_PUBLISH:
		return kclip_ioc_msg_publish(filp, arg);
	case KCLIP_IOC_MSG_FETCH:
		return kclip_ioc_msg_fetch(filp, arg);
	case KCLIP_IOC_MSG_ACK:
		return kclip_ioc_msg_ack(filp, arg);
	case KCLIP_IOC_MSG_CONSUME:
		return kclip_ioc_msg_consume(filp, arg);
	case KCLIP_IOC_BIND_SLOT:
		return kclip_ioc_bind_slot(filp, arg);
	case KCLIP_IOC_HEAD:
		return kclip_ioc_head(arg);
	case KCLIP_IOC_SLOT_LIST:
		return kclip_ioc_slot_list(arg);
	case KCLIP_IOC_LIMITS_GET:
		return kclip_ioc_limits_get(arg);
	case KCLIP_IOC_LIMITS_SET:
		return kclip_ioc_limits_set(arg);
	case KCLIP_IOC_STATS_GET:
		return kclip_ioc_stats_get(arg);
	case KCLIP_IOC_EVENTFD:
		return kclip_ioc_eventfd(arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations kclip_fops = {
	.owner          = THIS_MODULE,
	.open           = kclip_open,
	.release        = kclip_release,
	.poll           = kclip_poll,
	.unlocked_ioctl = kclip_ioctl,
};

/* ===== module init / exit ===== */
static int __init kclip_init(void)
{
	int ret;
	struct kclip_dev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	/* If you’re keeping a “slot0” for the skeleton poll path: */
	kclip_slot_init(&dev->slot0);

	g_dev = dev;

	dev->mdev.minor = MISC_DYNAMIC_MINOR;
	dev->mdev.name  = "kclip";
	dev->mdev.fops  = &kclip_fops;
	dev->mdev.mode  = 0666;

	ret = misc_register(&dev->mdev);
	if (ret) {
		kfree(dev);
		g_dev = NULL;
		return ret;
	}
	pr_info("kclip: registered /dev/kclip (ABI v%d)\n", UCLIP_ABI_VERSION);
	return 0;
}

static void __exit kclip_exit(void)
{
	struct kclip_dev *dev = g_dev;

	if (!dev)
		return;

	misc_deregister(&dev->mdev);

	/* drain the dummy slot if you used it */
	kclip_slot_fini(&dev->slot0);

	kfree(dev);
	g_dev = NULL;
	pr_info("kclip: unloaded\n");
}


module_init(kclip_init);
module_exit(kclip_exit);

MODULE_DESCRIPTION("kclip: misc device + poll + ioctl (stubs)");
MODULE_AUTHOR("Ben Hoff");
MODULE_LICENSE("GPL");

