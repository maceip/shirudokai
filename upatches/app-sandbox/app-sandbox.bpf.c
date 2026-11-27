// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * app-sandbox: a task that carries a sandbox's policy bit (optionally scoped
 * to Kubernetes Pod cgroup v2 IDs) executes only the files its sandbox names,
 * creates only the socket families it allows, connects only to the networks,
 * ports and UNIX sockets its rules permit, does not ptrace when denied, and
 * does not create, rename, read or write a file whose name matches a pattern
 * it denies. gen_policy.py writes sandbox_policy.
 */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "policy.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#define SANDBOX_MAX		32
#define SANDBOX_CGROUP_MAX	32
#define SANDBOX_CGROUP_DEPTH	12
#define SANDBOX_NET_MAX		128
#define SANDBOX_PORT_MAX	64
#define SANDBOX_FIM_MAX		64
#define SANDBOX_GLOB_MAX	32
#define SANDBOX_HEAD_MAX	64

#define SANDBOX_FIM_CREATE	0x1
#define SANDBOX_FIM_RENAME	0x2
#define SANDBOX_FIM_WRITE	0x4
#define SANDBOX_FIM_READ	0x8
#define SANDBOX_FIM_UNIX	0x10
#define SANDBOX_FIM_UNIX_PATH	0x20

#define SANDBOX_GLOB_EXACT	0
#define SANDBOX_GLOB_STAR	1
#define SANDBOX_GLOB_CONTAINS	2

#define SANDBOX_PROTO_TCP	0x1
#define SANDBOX_PROTO_UDP	0x2

#define EACCES			13
#define ENODATA			61
#define EOPNOTSUPP		95
#define AF_UNSPEC		0
#define AF_UNIX			1
#define AF_INET			2
#define AF_INET6		10
#define AF_NETLINK		16
#define AF_PACKET		17
#define AF_VSOCK		40
#define SOCK_RAW		3
#define SOCK_TYPE_MASK		0xf
#define IPPROTO_TCP		6
#define IPPROTO_UDP		17
#define IPPROTO_UDPLITE		136
#define IPPROTO_MPTCP		262
#define FMODE_READ		0x1
#define FMODE_WRITE		0x2
#define ATTR_SIZE		0x8
#define NAME_MAX		255
#define UNIX_PATH_MAX		108
#define SUN_PATH_OFFSET		2

/* gen_policy.py packs these structs byte for byte. */
struct sandbox_exec_rule {
	__u64	sandbox;
	__u64	allowed;
};

struct sandbox_family_rule {
	__u64	sandbox;
	__u64	allowed;
};

struct sandbox_cgroup_rule {
	__u64	cgroup_id;
	__u64	sandboxes;
};

/* An address in network byte order, IPv4 as ::ffff:a.b.c.d. */
union sandbox_addr {
	__u8	bytes[16];
	__be32	words[4];
	__u64	halves[2];
};

struct sandbox_net_rule {
	__u64	allow_sandboxes;
	__u64	deny_sandboxes;
	__u64	addr[2];
	__u64	mask[2];
};

struct sandbox_port_rule {
	__u64	allow_sandboxes;
	__u64	deny_sandboxes;
	__u16	start;
	__u16	end;
	__u8	protos;
	__u8	reserved[3];
};

struct sandbox_fim_rule {
	__u64	sandboxes;
	__u8	ops;
	__u8	prefix_len;
	__u8	suffix_len;
	__u8	wildcard;
	__u8	reserved[4];
	__u8	prefix[SANDBOX_GLOB_MAX];
	__u8	suffix[SANDBOX_GLOB_MAX];
};

struct sandbox_policy {
	__u64	sandboxes;
	__u64	cgroup_scoped;
	__u64	exec_enforced;
	__u64	families_enforced;
	__u64	net_enforced;
	__u64	net_deny_enforced;
	__u64	port_enforced;
	__u64	port_deny_enforced;
	__u64	read_enforced;
	__u64	unix_enforced;
	__u64	ptrace_denied;
	__u32	nr_exec;
	__u32	nr_families;
	__u32	nr_cgroup_ids;
	__u32	nr_net;
	__u32	nr_ports;
	__u32	nr_fim;
	struct sandbox_exec_rule	exec[SANDBOX_MAX];
	struct sandbox_family_rule	families[SANDBOX_MAX];
	struct sandbox_cgroup_rule	cgroup_ids[SANDBOX_CGROUP_MAX];
	struct sandbox_net_rule		net[SANDBOX_NET_MAX];
	struct sandbox_port_rule	ports[SANDBOX_PORT_MAX];
	struct sandbox_fim_rule		fim[SANDBOX_FIM_MAX];
};

const volatile struct sandbox_policy sandbox_policy = {};

struct sandbox_label {
	__u64	bits;
};

/* bpf_dynptr_from_mem() takes map memory only, and the exec hook sleeps. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sandbox_label);
} sandbox_label SEC(".maps");

/* Bounded head and tail slices of a file or UNIX socket name. */
struct sandbox_name {
	__u32	len;
	__u32	head_len;
	__u32	tail_len;
	__u8	head[SANDBOX_HEAD_MAX];
	__u8	tail[SANDBOX_GLOB_MAX];
};

int bpf_get_file_xattr(struct file *file, const char *name__str,
		       struct bpf_dynptr *value_p) __ksym;

static __always_inline __u64 cgroup_matches(__u64 cg)
{
	const volatile struct sandbox_cgroup_rule *rule;
	__u32 nr = sandbox_policy.nr_cgroup_ids;
	__u64 matched = 0;
	__u32 i;

	for (i = 0; i < SANDBOX_CGROUP_MAX; i++) {
		if (i >= nr)
			break;
		rule = &sandbox_policy.cgroup_ids[i];
		if (rule->cgroup_id == cg)
			matched |= rule->sandboxes;
	}
	return matched;
}

/*
 * bpf_get_current_ancestor_cgroup_id(level) reads cgrp->ancestors[level]:
 * level 0 is the root cgroup, levels 1..cgrp->level walk down through the
 * Pod's cgroup to the task's own cgroup, and levels past cgrp->level
 * return 0.
 */
static __always_inline __u64 current_cgroup_sandboxes(void)
{
	__u64 matched = 0, cg;
	__u32 level;

	for (level = 1; level <= SANDBOX_CGROUP_DEPTH; level++) {
		cg = bpf_get_current_ancestor_cgroup_id(level);
		if (!cg)
			break;
		matched |= cgroup_matches(cg);
	}
	return matched;
}

static __always_inline __u64 current_sandboxes(void)
{
	struct task_policy *policy;
	__u64 active, scoped;

	policy = bpf_task_storage_get(&shirudo_task_policy,
				      bpf_get_current_task_btf(), NULL, 0);
	if (!policy)
		return 0;
	active = policy->active & sandbox_policy.sandboxes;
	scoped = active & sandbox_policy.cgroup_scoped;
	if (scoped)
		active = (active & ~scoped) |
			 (scoped & current_cgroup_sandboxes());
	return active;
}

static __always_inline __u64 peer_gate_mask(void)
{
	return sandbox_policy.net_enforced |
	       sandbox_policy.net_deny_enforced |
	       sandbox_policy.port_enforced |
	       sandbox_policy.port_deny_enforced;
}

static __always_inline int file_policy_bits(struct file *file, __u64 *bits)
{
	struct sandbox_label *label;
	struct bpf_dynptr value;
	int len;

	label = bpf_task_storage_get(&sandbox_label,
				     bpf_get_current_task_btf(), NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!label ||
	    bpf_dynptr_from_mem(&label->bits, sizeof(label->bits), 0, &value))
		return -EACCES;
	len = bpf_get_file_xattr(file, XATTR_POLICY, &value);
	if (len == -ENODATA || len == -EOPNOTSUPP) {
		*bits = 0;
		return 0;
	}
	if (len != sizeof(label->bits))
		return -EACCES;
	*bits = label->bits;
	return 0;
}

static __always_inline bool exec_allowed(__u64 sandboxes, __u64 file_bits)
{
	const volatile struct sandbox_exec_rule *rule;
	__u32 nr_exec = sandbox_policy.nr_exec;
	__u32 i;

	for (i = 0; i < SANDBOX_MAX; i++) {
		if (i >= nr_exec)
			break;
		rule = &sandbox_policy.exec[i];
		if ((sandboxes & rule->sandbox) && !(file_bits & rule->allowed))
			return false;
	}
	return true;
}

/* The kernel calls it for a script and again for each interpreter. */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(sandbox_exec, struct linux_binprm *bprm, int ret)
{
	__u64 sandboxes, file_bits;

	if (ret)
		return ret;
	sandboxes = current_sandboxes() & sandbox_policy.exec_enforced;
	if (!sandboxes)
		return 0;
	if (!bprm->file || file_policy_bits(bprm->file, &file_bits))
		return -EACCES;
	return exec_allowed(sandboxes, file_bits) ? 0 : -EACCES;
}

static __always_inline bool net_allowed(__u64 sandboxes,
					const union sandbox_addr *addr)
{
	const volatile struct sandbox_net_rule *rule;
	__u32 nr_net = sandbox_policy.nr_net;
	__u64 allowed = 0;
	__u32 i;

	for (i = 0; i < SANDBOX_NET_MAX; i++) {
		if (i >= nr_net)
			break;
		rule = &sandbox_policy.net[i];
		if ((addr->halves[0] & rule->mask[0]) == rule->addr[0] &&
		    (addr->halves[1] & rule->mask[1]) == rule->addr[1]) {
			if (rule->deny_sandboxes & sandboxes)
				return false;
			allowed |= rule->allow_sandboxes;
		}
	}
	return !((sandboxes & sandbox_policy.net_enforced) & ~allowed);
}

static __always_inline bool port_allowed(__u64 sandboxes, struct socket *sock,
					 __u16 port)
{
	const volatile struct sandbox_port_rule *rule;
	__u32 nr_ports = sandbox_policy.nr_ports;
	struct sock *sk = sock ? sock->sk : NULL;
	__u16 sk_proto = sk ? sk->sk_protocol : 0;
	__u64 allowed = 0;
	__u8 proto_bit;
	__u32 i;

	if (sk_proto == IPPROTO_TCP || sk_proto == IPPROTO_MPTCP)
		proto_bit = SANDBOX_PROTO_TCP;
	else if (sk_proto == IPPROTO_UDP || sk_proto == IPPROTO_UDPLITE)
		proto_bit = SANDBOX_PROTO_UDP;
	else
		proto_bit = 0;
	if (!proto_bit)
		return !(sandboxes & sandbox_policy.port_enforced);

	for (i = 0; i < SANDBOX_PORT_MAX; i++) {
		if (i >= nr_ports)
			break;
		rule = &sandbox_policy.ports[i];
		if ((rule->protos & proto_bit) &&
		    port >= rule->start && port <= rule->end) {
			if (rule->deny_sandboxes & sandboxes)
				return false;
			allowed |= rule->allow_sandboxes;
		}
	}
	return !((sandboxes & sandbox_policy.port_enforced) & ~allowed);
}

static __always_inline int peer_verdict(__u64 sandboxes, struct socket *sock,
					__u16 family,
					const struct sockaddr *address,
					int addrlen)
{
	union sandbox_addr addr = {};
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	__u16 port;

	if (family == AF_INET) {
		if (addrlen < (int)sizeof(sin) ||
		    bpf_probe_read_kernel(&sin, sizeof(sin), address))
			return -EACCES;
		addr.words[2] = bpf_htonl(0xffff);
		addr.words[3] = sin.sin_addr.s_addr;
		port = bpf_ntohs(sin.sin_port);
	} else if (family == AF_INET6) {
		if (addrlen < (int)sizeof(sin6) ||
		    bpf_probe_read_kernel(&sin6, sizeof(sin6), address))
			return -EACCES;
		__builtin_memcpy(addr.bytes, &sin6.sin6_addr,
				 sizeof(addr.bytes));
		port = bpf_ntohs(sin6.sin6_port);
	} else {
		return 0;
	}
	if ((sandboxes & (sandbox_policy.net_enforced |
			  sandbox_policy.net_deny_enforced)) &&
	    !net_allowed(sandboxes, &addr))
		return -EACCES;
	if ((sandboxes & (sandbox_policy.port_enforced |
			  sandbox_policy.port_deny_enforced)) &&
	    !port_allowed(sandboxes, sock, port))
		return -EACCES;
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(sandbox_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	__u64 sandboxes;
	__u16 family;

	if (ret)
		return ret;
	sandboxes = current_sandboxes() & peer_gate_mask();
	if (!sandboxes)
		return 0;
	if (!address || addrlen < (int)sizeof(family) ||
	    bpf_probe_read_kernel(&family, sizeof(family),
				  &address->sa_family))
		return -EACCES;
	return peer_verdict(sandboxes, sock, family, address, addrlen);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(sandbox_sendmsg, struct socket *sock, struct msghdr *msg,
	     int size, int ret)
{
	struct sockaddr *address;
	__u64 sandboxes;
	struct sock *sk;
	__u16 family;
	int addrlen;

	if (ret)
		return ret;
	address = msg->msg_name;
	if (!address)
		return 0;
	sandboxes = current_sandboxes() & peer_gate_mask();
	if (!sandboxes)
		return 0;
	addrlen = msg->msg_namelen;
	if (addrlen < (int)sizeof(family) ||
	    bpf_probe_read_kernel(&family, sizeof(family),
				  &address->sa_family))
		return -EACCES;
	/* IPv4 sends to an AF_UNSPEC address as to an AF_INET one. */
	sk = sock->sk;
	if (family == AF_UNSPEC && sk && sk->__sk_common.skc_family == AF_INET)
		family = AF_INET;
	return peer_verdict(sandboxes, sock, family, address, addrlen);
}

static __always_inline bool family_allowed(__u64 sandboxes, int family)
{
	const volatile struct sandbox_family_rule *rule;
	__u32 nr_families = sandbox_policy.nr_families;
	__u64 bit;
	__u32 i;

	if (family < 0 || family >= 64)
		return false;
	bit = 1ULL << (__u32)family;
	for (i = 0; i < SANDBOX_MAX; i++) {
		if (i >= nr_families)
			break;
		rule = &sandbox_policy.families[i];
		if ((sandboxes & rule->sandbox) && !(rule->allowed & bit))
			return false;
	}
	return true;
}

/*
 * Enforce per-sandbox socket address-family allowmasks and refuse raw or
 * packet sockets whenever network or port filtering is active.
 */
SEC("lsm/socket_create")
int BPF_PROG(sandbox_socket_create, int family, int type, int protocol,
	     int kern, int ret)
{
	bool raw_or_packet;
	__u64 sandboxes;

	if (ret || kern)
		return ret;
	raw_or_packet = family == AF_PACKET ||
			((family == AF_INET || family == AF_INET6) &&
			 (type & SOCK_TYPE_MASK) == SOCK_RAW);
	if (!raw_or_packet && !sandbox_policy.families_enforced)
		return 0;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	if (raw_or_packet && (sandboxes & peer_gate_mask()))
		return -EACCES;
	if ((sandboxes & sandbox_policy.families_enforced) &&
	    !family_allowed(sandboxes & sandbox_policy.families_enforced,
			    family))
		return -EACCES;
	return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(sandbox_ptrace, struct task_struct *child, __u32 mode, int ret)
{
	if (ret || !sandbox_policy.ptrace_denied)
		return ret;
	return current_sandboxes() & sandbox_policy.ptrace_denied ? -EACCES : 0;
}

static __always_inline int read_name(struct dentry *dentry,
				     struct sandbox_name *name)
{
	const __u8 *bytes = dentry->d_name.name;
	__u32 len = dentry->d_name.len;
	__u32 head_len, tail_len;

	if (!len || len > NAME_MAX)
		return -EACCES;
	head_len = len;
	if (head_len > SANDBOX_HEAD_MAX)
		head_len = SANDBOX_HEAD_MAX;
	tail_len = len;
	if (tail_len > SANDBOX_GLOB_MAX)
		tail_len = SANDBOX_GLOB_MAX;
	if (bpf_probe_read_kernel(name->head, head_len, bytes) ||
	    bpf_probe_read_kernel(name->tail, tail_len, bytes + len - tail_len))
		return -EACCES;
	name->len = len;
	name->head_len = head_len;
	name->tail_len = tail_len;
	return 0;
}

static __always_inline bool byte_matches(__u8 pattern, __u8 byte)
{
	return pattern == '?' || pattern == byte;
}

static __noinline bool
name_contains(const volatile struct sandbox_fim_rule *rule,
	      const struct sandbox_name *name)
{
	__u32 nlen = rule->prefix_len;
	__u32 hlen = name->head_len;
	__u32 pos, j;

	if (!nlen || nlen > SANDBOX_GLOB_MAX || hlen < nlen)
		return false;
	for (pos = 0; pos < SANDBOX_HEAD_MAX; pos++) {
		if (pos + nlen > hlen)
			break;
		for (j = 0; j < SANDBOX_GLOB_MAX; j++) {
			if (j >= nlen)
				return true;
			if (!byte_matches(rule->prefix[j],
					  name->head[(pos + j) &
						     (SANDBOX_HEAD_MAX - 1)]))
				break;
		}
		if (j == nlen)
			return true;
	}
	return false;
}

static __always_inline bool
name_matches(const volatile struct sandbox_fim_rule *rule,
	     const struct sandbox_name *name)
{
	__u32 prefix_len = rule->prefix_len;
	__u32 suffix_len = rule->suffix_len;
	__u32 i, tail_at;

	if (rule->wildcard == SANDBOX_GLOB_CONTAINS)
		return name_contains(rule, name);
	if (prefix_len > SANDBOX_GLOB_MAX || suffix_len > SANDBOX_GLOB_MAX)
		return true;
	if (rule->wildcard ? name->len < prefix_len + suffix_len :
			     name->len != prefix_len)
		return false;
	for (i = 0; i < SANDBOX_GLOB_MAX; i++) {
		if (i >= prefix_len)
			break;
		if (!byte_matches(rule->prefix[i], name->head[i]))
			return false;
	}
	tail_at = name->tail_len - suffix_len;
	for (i = 0; i < SANDBOX_GLOB_MAX; i++) {
		if (i >= suffix_len)
			break;
		if (!byte_matches(rule->suffix[i],
				  name->tail[(tail_at + i) &
					     (SANDBOX_GLOB_MAX - 1)]))
			return false;
	}
	return true;
}

static __noinline bool name_denied(__u64 sandboxes, __u32 op,
				   struct dentry *dentry)
{
	const volatile struct sandbox_fim_rule *rule;
	__u32 nr_fim = sandbox_policy.nr_fim;
	struct sandbox_name name = {};
	__u32 i;

	if (!dentry || read_name(dentry, &name))
		return true;
	for (i = 0; i < SANDBOX_FIM_MAX; i++) {
		if (i >= nr_fim)
			break;
		rule = &sandbox_policy.fim[i];
		if ((rule->sandboxes & sandboxes) && (rule->ops & op) &&
		    name_matches(rule, &name))
			return true;
	}
	return false;
}

static __noinline bool unix_addr_denied(__u64 sandboxes,
					struct unix_address *uaddr,
					bool check_basename)
{
	const volatile struct sandbox_fim_rule *rule;
	__u32 nr_fim = sandbox_policy.nr_fim;
	__u8 raw[UNIX_PATH_MAX] = {};
	struct sandbox_name full = {};
	struct sandbox_name base = {};
	__u32 len, head_len, tail_len, base_off = 0, base_len;
	int addr_len;
	__u32 i;

	if (bpf_probe_read_kernel(&addr_len, sizeof(addr_len), &uaddr->len))
		return true;
	if (addr_len <= SUN_PATH_OFFSET)
		return false;
	len = (__u32)(addr_len - SUN_PATH_OFFSET);
	if (len > UNIX_PATH_MAX)
		len = UNIX_PATH_MAX;
	if (bpf_probe_read_kernel(raw, len, uaddr->name[0].sun_path))
		return true;
	if (raw[0] == '\0')
		raw[0] = '@';
	else if (len > 1 && raw[len - 1] == '\0')
		len--;
	if (!len || len > UNIX_PATH_MAX)
		return false;

	head_len = len;
	if (head_len > SANDBOX_HEAD_MAX)
		head_len = SANDBOX_HEAD_MAX;
	tail_len = len;
	if (tail_len > SANDBOX_GLOB_MAX)
		tail_len = SANDBOX_GLOB_MAX;
	if (bpf_probe_read_kernel(full.head, head_len,
				  uaddr->name[0].sun_path) ||
	    bpf_probe_read_kernel(full.tail, tail_len,
				  uaddr->name[0].sun_path + len - tail_len))
		return true;
	if (full.head[0] == '\0')
		full.head[0] = '@';
	if (len == tail_len && full.tail[0] == '\0')
		full.tail[0] = '@';
	full.len = len;
	full.head_len = head_len;
	full.tail_len = tail_len;

	if (check_basename) {
		for (i = 0; i < UNIX_PATH_MAX; i++) {
			if (i >= len)
				break;
			if (raw[i] == '/')
				base_off = i + 1;
		}
		if (base_off < len) {
			base_len = len - base_off;
			head_len = base_len;
			if (head_len > SANDBOX_HEAD_MAX)
				head_len = SANDBOX_HEAD_MAX;
			tail_len = base_len;
			if (tail_len > SANDBOX_GLOB_MAX)
				tail_len = SANDBOX_GLOB_MAX;
			if (bpf_probe_read_kernel(base.head, head_len,
						  uaddr->name[0].sun_path +
						  base_off) ||
			    bpf_probe_read_kernel(base.tail, tail_len,
						  uaddr->name[0].sun_path +
						  len - tail_len))
				return true;
			if (!base_off && base.head[0] == '\0')
				base.head[0] = '@';
			if (!base_off && base_len == tail_len &&
			    base.tail[0] == '\0')
				base.tail[0] = '@';
			base.len = base_len;
			base.head_len = head_len;
			base.tail_len = tail_len;
		}
	}

	for (i = 0; i < SANDBOX_FIM_MAX; i++) {
		if (i >= nr_fim)
			break;
		rule = &sandbox_policy.fim[i];
		if (!(rule->sandboxes & sandboxes))
			continue;
		if ((rule->ops & SANDBOX_FIM_UNIX_PATH) &&
		    name_matches(rule, &full))
			return true;
		if (check_basename && base.len &&
		    (rule->ops & SANDBOX_FIM_UNIX) &&
		    name_matches(rule, &base))
			return true;
	}
	return false;
}

static __always_inline int unix_peer_verdict(struct sock *peer_sk)
{
	const struct unix_sock *u = (const struct unix_sock *)peer_sk;
	struct unix_address *uaddr;
	struct dentry *dentry;
	__u64 sandboxes;

	if (!sandbox_policy.unix_enforced)
		return 0;
	sandboxes = current_sandboxes() & sandbox_policy.unix_enforced;
	if (!sandboxes)
		return 0;
	if (!u)
		return -EACCES;
	dentry = u->path.dentry;
	if (dentry && name_denied(sandboxes, SANDBOX_FIM_UNIX, dentry))
		return -EACCES;
	uaddr = u->addr;
	if (uaddr && unix_addr_denied(sandboxes, uaddr, !dentry))
		return -EACCES;
	return 0;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(sandbox_unix_connect, struct sock *sock, struct sock *other,
	     struct sock *newsk, int ret)
{
	return ret ? ret : unix_peer_verdict(other);
}

SEC("lsm/unix_may_send")
int BPF_PROG(sandbox_unix_send, struct socket *sock, struct socket *other,
	     int ret)
{
	if (ret)
		return ret;
	return unix_peer_verdict(other ? other->sk : NULL);
}

static __always_inline int name_verdict(__u32 op, struct dentry *dentry)
{
	__u64 sandboxes = current_sandboxes();

	if (!sandboxes)
		return 0;
	return name_denied(sandboxes, op, dentry) ? -EACCES : 0;
}

SEC("lsm/inode_create")
int BPF_PROG(sandbox_create, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(sandbox_mkdir, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_symlink")
int BPF_PROG(sandbox_symlink, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, const char *old_name, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_mknod")
int BPF_PROG(sandbox_mknod, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, dev_t dev, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_link")
int BPF_PROG(sandbox_link, struct mnt_idmap *idmap, struct dentry *old_dentry,
	     struct inode *dir, struct dentry *new_dentry, int ret)
{
	__u64 sandboxes, read_sb;

	if (ret)
		return ret;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	if (name_denied(sandboxes, SANDBOX_FIM_CREATE, new_dentry) ||
	    name_denied(sandboxes, SANDBOX_FIM_WRITE, old_dentry))
		return -EACCES;
	read_sb = sandboxes & sandbox_policy.read_enforced;
	if (read_sb && name_denied(read_sb, SANDBOX_FIM_READ, old_dentry))
		return -EACCES;
	return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(sandbox_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, int ret)
{
	__u64 sandboxes;

	if (ret)
		return ret;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	if (name_denied(sandboxes, SANDBOX_FIM_RENAME, old_dentry) ||
	    name_denied(sandboxes, SANDBOX_FIM_RENAME, new_dentry))
		return -EACCES;
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(sandbox_open, struct file *file, int ret)
{
	__u64 sandboxes, read_sb;
	struct dentry *dentry;
	fmode_t mode;

	if (ret)
		return ret;
	mode = file->f_mode;
	if (!(mode & FMODE_WRITE) && !sandbox_policy.read_enforced)
		return 0;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	dentry = file->f_path.dentry;
	if ((mode & FMODE_WRITE) &&
	    name_denied(sandboxes, SANDBOX_FIM_WRITE, dentry))
		return -EACCES;
	read_sb = sandboxes & sandbox_policy.read_enforced;
	if ((mode & FMODE_READ) && read_sb &&
	    name_denied(read_sb, SANDBOX_FIM_READ, dentry))
		return -EACCES;
	return 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(sandbox_truncate, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr, int ret)
{
	if (ret || !(attr->ia_valid & ATTR_SIZE))
		return ret;
	return name_verdict(SANDBOX_FIM_WRITE, dentry);
}
