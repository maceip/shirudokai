/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Reusable shield counters, call-stack capture and observe/enforce decision
 * helpers. On the BPF side, include after vmlinux.h and <bpf/bpf_helpers.h>.
 */

#ifndef SHIRUDO_BPF_SHIELD_H
#define SHIRUDO_BPF_SHIELD_H

#ifndef __BPF__
#include <shirudo/types.h>
#endif

#define SHIELD_STACK_MAX_DEPTH	127

struct shield_counters {
	__u64 activity;
	__u64 hits;
	__u64 enforced;
	__u64 observed;
};

#ifdef __BPF__

#ifndef EEXIST
#define EEXIST	17
#endif

#define SHIELD_COUNTERS_MAP(name)					\
	struct {							\
		__uint(type, BPF_MAP_TYPE_ARRAY);			\
		__uint(max_entries, 1);					\
		__type(key, __u32);					\
		__type(value, struct shield_counters);			\
	} name SEC(".maps")

#define SHIELD_STACK_MAP(name, max_entries_nr)				\
	struct {							\
		__uint(type, BPF_MAP_TYPE_STACK_TRACE);			\
		__uint(max_entries, (max_entries_nr));			\
		__uint(key_size, sizeof(__u32));			\
		__uint(value_size, SHIELD_STACK_MAX_DEPTH * sizeof(__u64)); \
	} name SEC(".maps")

#define SHIELD_STACK_ID_COUNTS_MAP(name, max_entries_nr)		\
	struct {							\
		__uint(type, BPF_MAP_TYPE_HASH);			\
		__uint(max_entries, (max_entries_nr));			\
		__type(key, __u32);					\
		__type(value, __u64);					\
	} name SEC(".maps")

static __always_inline void shield_count_activity(void *counters_map)
{
	struct shield_counters *c;
	__u32 zero = 0;

	if (!counters_map)
		return;
	c = bpf_map_lookup_elem(counters_map, &zero);
	if (c)
		__sync_fetch_and_add(&c->activity, 1);
}

static __always_inline void shield_record_stack_id(void *stack_ids_map,
						   __u32 stack_id)
{
	__u64 init = 1;
	__u64 *cnt;

	if (!stack_ids_map)
		return;
	cnt = bpf_map_lookup_elem(stack_ids_map, &stack_id);
	if (cnt) {
		__sync_fetch_and_add(cnt, 1);
		return;
	}
	if (bpf_map_update_elem(stack_ids_map, &stack_id, &init,
				BPF_NOEXIST) == -EEXIST) {
		cnt = bpf_map_lookup_elem(stack_ids_map, &stack_id);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
	}
}

/*
 * Capture the current kernel (flags == 0) or user (flags & BPF_F_USER_STACK)
 * call stack into stack_map, optionally counting unique stack IDs in
 * stack_ids_map so operators can narrow blocks by caller stack.
 */
static __always_inline __s64 shield_capture_stack(void *ctx, void *stack_map,
						  __u64 flags,
						  void *stack_ids_map)
{
	__s64 id;

	if (!ctx || !stack_map)
		return -1;
	id = bpf_get_stackid(ctx, stack_map, flags);
	if (id >= 0 && stack_ids_map)
		shield_record_stack_id(stack_ids_map, (__u32)id);
	return id;
}

/*
 * True when the caller's stack ID is present in narrow_stack_ids_map, for
 * narrowing enforcement to caller stacks observed during a reproducer run.
 */
static __always_inline bool shield_stack_matches(void *ctx, void *stack_map,
						 __u64 flags,
						 void *narrow_stack_ids_map)
{
	__u32 stack_id;
	__s64 id;

	if (!ctx || !stack_map || !narrow_stack_ids_map)
		return false;
	id = bpf_get_stackid(ctx, stack_map, flags);
	if (id < 0)
		return false;
	stack_id = (__u32)id;
	return bpf_map_lookup_elem(narrow_stack_ids_map, &stack_id);
}

static __always_inline int shield_decide_stack(bool observe, void *counters_map,
					       void *stack_map,
					       void *stack_ids_map,
					       __u64 stack_flags,
					       void *ctx, int err)
{
	struct shield_counters *c;
	int deny = err < 0 ? err : -err;
	__u32 zero = 0;

	if (counters_map) {
		c = bpf_map_lookup_elem(counters_map, &zero);
		if (c) {
			__sync_fetch_and_add(&c->hits, 1);
			if (observe)
				__sync_fetch_and_add(&c->observed, 1);
			else
				__sync_fetch_and_add(&c->enforced, 1);
		}
	}
	if (stack_map && ctx)
		shield_capture_stack(ctx, stack_map, stack_flags,
				     stack_ids_map);
	return observe ? 0 : deny;
}

static __always_inline int shield_decide(bool observe, void *counters_map,
					 void *stack_map, void *ctx, int err)
{
	return shield_decide_stack(observe, counters_map, stack_map, NULL, 0,
				   ctx, err);
}

#endif /* __BPF__ */
#endif /* SHIRUDO_BPF_SHIELD_H */
