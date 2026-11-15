#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define PATH_LEN 256
#define DNAME_LEN 64
#define MODULE_NAME_LEN 56
#define MAX_SYSCALL 1024
#define PF_KTHREAD 0x00200000
#define FLAG_WATCH 1u
#define FLAG_TRACE 2u

enum event_kind {
	EV_EXEC = 1,
	EV_CREDS = 2,
	EV_SYSCALL = 3,
	EV_MODULE = 4,
	EV_WATCH = 5,
};

typedef struct {
	__u32 val;
} kuid_t;

typedef struct {
	__u64 val;
} kernel_cap_t;

struct user_namespace {
	int level;
} __attribute__((preserve_access_index));

struct cred {
	kuid_t uid;
	kuid_t suid;
	kuid_t euid;
	kuid_t fsuid;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	struct user_namespace *user_ns;
} __attribute__((preserve_access_index));

struct thread_info {
	__u32 status;
} __attribute__((preserve_access_index));

struct task_struct {
	struct thread_info thread_info;
	unsigned int flags;
	int pid;
	int tgid;
	struct task_struct *real_parent;
	const struct cred *cred;
	char comm[TASK_COMM_LEN];
} __attribute__((preserve_access_index));

struct qstr {
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
	struct qstr d_name;
} __attribute__((preserve_access_index));

struct path {
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct inode {
	unsigned int i_nlink;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
	const char *filename;
} __attribute__((preserve_access_index));

struct module {
	char name[MODULE_NAME_LEN];
	unsigned long taints;
} __attribute__((preserve_access_index));

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long di;
	unsigned long si;
	unsigned long dx;
	unsigned long r10;
	unsigned long r8;
	unsigned long r9;
	unsigned long orig_ax;
} __attribute__((preserve_access_index));
#define KPROBE_ARG1(r) ((r)->di)
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
	unsigned long regs[31];
	unsigned long pstate;
	int syscallno;
} __attribute__((preserve_access_index));
#define KPROBE_ARG1(r) ((r)->regs[0])
#else
#error "kernguard BPF programs support x86_64 and arm64 only"
#endif

struct hdr {
	__u32 kind;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u64 ts;
	char comm[TASK_COMM_LEN];
};

struct exec_event {
	struct hdr h;
	__u32 ppid;
	__u32 euid;
	__u32 nlink;
	__u32 pad;
	char filename[PATH_LEN];
	char dname[DNAME_LEN];
};

struct creds_event {
	struct hdr h;
	__s64 syscall;
	__u32 old_uid;
	__u32 old_euid;
	__u32 old_suid;
	__u32 old_fsuid;
	__u32 new_uid;
	__u32 new_euid;
	__u32 new_suid;
	__u32 new_fsuid;
	__u64 old_cap_eff;
	__u64 old_cap_prm;
	__u64 new_cap_eff;
	__u32 new_userns_level;
	__u32 compat;
};

struct syscall_event {
	struct hdr h;
	__s64 nr;
	__u64 args[6];
	__s64 ret;
	__u64 duration;
	char path[PATH_LEN];
};

struct watch_event {
	struct hdr h;
	__s64 nr;
	__u64 args[6];
	char path[PATH_LEN];
};

struct module_event {
	struct hdr h;
	__u64 taints;
	char name[MODULE_NAME_LEN];
};

struct inflight {
	__s64 nr;
	__u64 ts;
	__u64 args[6];
	char path[PATH_LEN];
};

struct config {
	__u32 self_tgid;
	__u32 pad;
};

_Static_assert(sizeof(struct hdr) == 40, "hdr layout");
_Static_assert(sizeof(struct exec_event) == 376, "exec layout");
_Static_assert(sizeof(struct creds_event) == 112, "creds layout");
_Static_assert(sizeof(struct syscall_event) == 368, "syscall layout");
_Static_assert(sizeof(struct watch_event) == 352, "watch layout");
_Static_assert(sizeof(struct module_event) == 104, "module layout");
_Static_assert(__builtin_offsetof(struct creds_event, new_cap_eff) == 96, "creds caps offset");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SYSCALL);
	__type(key, __u32);
	__type(value, __u32);
} syscall_flags SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} traced SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct inflight);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct inflight);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void *reserve(__u64 size)
{
	void *e = bpf_ringbuf_reserve(&events, size, 0);
	if (!e) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&drops, &zero);
		if (n)
			*n += 1;
	}
	return e;
}

static __always_inline void fill_hdr(struct hdr *h, __u32 kind, struct task_struct *t)
{
	h->kind = kind;
	h->pid = BPF_CORE_READ(t, pid);
	h->tgid = BPF_CORE_READ(t, tgid);
	h->uid = BPF_CORE_READ(t, cred, uid.val);
	h->ts = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(h->comm, sizeof(h->comm));
}

static __always_inline int is_self(__u32 tgid)
{
	__u32 zero = 0;
	struct config *cfg = bpf_map_lookup_elem(&config, &zero);
	return cfg && cfg->self_tgid == tgid;
}

static __always_inline void read_args(struct pt_regs *regs, __u64 *args)
{
#if defined(__TARGET_ARCH_x86)
	args[0] = BPF_CORE_READ(regs, di);
	args[1] = BPF_CORE_READ(regs, si);
	args[2] = BPF_CORE_READ(regs, dx);
	args[3] = BPF_CORE_READ(regs, r10);
	args[4] = BPF_CORE_READ(regs, r8);
	args[5] = BPF_CORE_READ(regs, r9);
#else
	args[0] = BPF_CORE_READ(regs, regs[0]);
	args[1] = BPF_CORE_READ(regs, regs[1]);
	args[2] = BPF_CORE_READ(regs, regs[2]);
	args[3] = BPF_CORE_READ(regs, regs[3]);
	args[4] = BPF_CORE_READ(regs, regs[4]);
	args[5] = BPF_CORE_READ(regs, regs[5]);
#endif
}

static __always_inline void read_path(char *dst, const __u64 *args, __u32 idx)
{
	__u64 ptr = 0;
	dst[0] = 0;
#pragma unroll
	for (int i = 0; i < 6; i++) {
		if ((__u32)i + 1 == idx)
			ptr = args[i];
	}
	if (ptr)
		bpf_probe_read_user_str(dst, PATH_LEN, (const void *)ptr);
}

static __always_inline __s64 syscall_nr(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_x86)
	return (__s64)BPF_CORE_READ(regs, orig_ax);
#else
	return (__s64)BPF_CORE_READ(regs, syscallno);
#endif
}

static __always_inline __u32 is_compat(struct task_struct *t, struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_x86)
	if (bpf_core_field_exists(t->thread_info.status))
		return (BPF_CORE_READ(t, thread_info.status) & 0x0002) != 0;
	return 0;
#else
	return (BPF_CORE_READ(regs, pstate) & 0x10) != 0;
#endif
}

SEC("tp_btf/sched_process_exec")
int on_exec(__u64 *ctx)
{
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[2];
	struct task_struct *t = bpf_get_current_task_btf();
	struct exec_event *e = reserve(sizeof(*e));
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_EXEC, t);
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	e->euid = BPF_CORE_READ(t, cred, euid.val);
	e->pad = 0;
	e->filename[0] = 0;
	e->dname[0] = 0;
	struct file *f = BPF_CORE_READ(bprm, file);
	e->nlink = BPF_CORE_READ(f, f_inode, i_nlink);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));
	bpf_probe_read_kernel_str(e->dname, sizeof(e->dname), BPF_CORE_READ(f, f_path.dentry, d_name.name));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/commit_creds")
int on_commit_creds(struct pt_regs *ctx)
{
	const struct cred *new = (const struct cred *)KPROBE_ARG1(ctx);
	struct task_struct *t = bpf_get_current_task_btf();
	if (BPF_CORE_READ(t, flags) & PF_KTHREAD)
		return 0;
	const struct cred *old = BPF_CORE_READ(t, cred);
	__u32 ou = BPF_CORE_READ(old, uid.val);
	__u32 oe = BPF_CORE_READ(old, euid.val);
	__u32 of = BPF_CORE_READ(old, fsuid.val);
	__u32 nu = BPF_CORE_READ(new, uid.val);
	__u32 ne = BPF_CORE_READ(new, euid.val);
	__u32 nf = BPF_CORE_READ(new, fsuid.val);
	__u64 oce = 0, ocp = 0, nce = 0;
	bpf_core_read(&oce, sizeof(oce), &old->cap_effective);
	bpf_core_read(&ocp, sizeof(ocp), &old->cap_permitted);
	bpf_core_read(&nce, sizeof(nce), &new->cap_effective);
	int gained = (ne == 0 && oe != 0) || (nu == 0 && ou != 0) || (nf == 0 && of != 0) || (nce & ~oce);
	if (!gained)
		return 0;
	struct creds_event *e = reserve(sizeof(*e));
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_CREDS, t);
	struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(t);
	e->syscall = syscall_nr(regs);
	e->compat = is_compat(t, regs);
	e->old_uid = ou;
	e->old_euid = oe;
	e->old_suid = BPF_CORE_READ(old, suid.val);
	e->old_fsuid = of;
	e->new_uid = nu;
	e->new_euid = ne;
	e->new_suid = BPF_CORE_READ(new, suid.val);
	e->new_fsuid = nf;
	e->old_cap_eff = oce;
	e->old_cap_prm = ocp;
	e->new_cap_eff = nce;
	e->new_userns_level = BPF_CORE_READ(new, user_ns, level);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/module_load")
int on_module_load(__u64 *ctx)
{
	struct module *mod = (struct module *)ctx[0];
	struct module_event *e = reserve(sizeof(*e));
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_MODULE, bpf_get_current_task_btf());
	e->taints = BPF_CORE_READ(mod, taints);
	e->name[0] = 0;
	BPF_CORE_READ_STR_INTO(&e->name, mod, name);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int on_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	long nr = (long)ctx->args[1];
	if (nr < 0 || nr >= MAX_SYSCALL)
		return 0;
	__u32 key = (__u32)nr;
	__u32 *flags = bpf_map_lookup_elem(&syscall_flags, &key);
	if (!flags)
		return 0;
	__u32 f = *flags;
	if (!(f & (FLAG_WATCH | FLAG_TRACE)))
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	int traced_task = (f & FLAG_TRACE) && bpf_map_lookup_elem(&traced, &tgid) != 0;
	if (!(f & FLAG_WATCH) && !traced_task)
		return 0;
	if (is_self(tgid))
		return 0;
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__u32 path_idx = (f >> 8) & 0xff;
	if (f & FLAG_WATCH) {
		struct watch_event *e = reserve(sizeof(*e));
		if (e) {
			fill_hdr(&e->h, EV_WATCH, bpf_get_current_task_btf());
			e->nr = nr;
			read_args(regs, e->args);
			read_path(e->path, e->args, path_idx);
			bpf_ringbuf_submit(e, 0);
		}
	}
	if (traced_task) {
		__u32 zero = 0;
		struct inflight *in = bpf_map_lookup_elem(&scratch, &zero);
		if (!in)
			return 0;
		in->nr = nr;
		in->ts = bpf_ktime_get_boot_ns();
		read_args(regs, in->args);
		read_path(in->path, in->args, path_idx);
		bpf_map_update_elem(&inflight, &id, in, BPF_ANY);
	}
	return 0;
}

SEC("raw_tracepoint/sys_exit")
int on_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct inflight *in = bpf_map_lookup_elem(&inflight, &id);
	if (!in)
		return 0;
	struct syscall_event *e = reserve(sizeof(*e));
	if (e) {
		fill_hdr(&e->h, EV_SYSCALL, bpf_get_current_task_btf());
		e->nr = in->nr;
		__builtin_memcpy(e->args, in->args, sizeof(e->args));
		e->ret = (__s64)ctx->args[1];
		e->duration = e->h.ts - in->ts;
		__builtin_memcpy(e->path, in->path, sizeof(e->path));
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&inflight, &id);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int on_fork(__u64 *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx[0];
	struct task_struct *child = (struct task_struct *)ctx[1];
	__u32 ptgid = BPF_CORE_READ(parent, tgid);
	if (!bpf_map_lookup_elem(&traced, &ptgid))
		return 0;
	__u32 ctgid = BPF_CORE_READ(child, tgid);
	if ((__u32)BPF_CORE_READ(child, pid) != ctgid)
		return 0;
	__u8 one = 1;
	bpf_map_update_elem(&traced, &ctgid, &one, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int on_exit(__u64 *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx[0];
	__u32 pid = BPF_CORE_READ(p, pid);
	__u32 tgid = BPF_CORE_READ(p, tgid);
	__u64 id = ((__u64)tgid << 32) | pid;
	bpf_map_delete_elem(&inflight, &id);
	if (pid == tgid)
		bpf_map_delete_elem(&traced, &tgid);
	return 0;
}
