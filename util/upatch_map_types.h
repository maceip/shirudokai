/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared BPF map type labels and generic-read policy for upatch map views.
 */

#ifndef SHIRUDO_UTIL_UPATCH_MAP_TYPES_H
#define SHIRUDO_UTIL_UPATCH_MAP_TYPES_H

#include <linux/bpf.h>
#include <stddef.h>

#include <shirudo/misc.h>

static inline const char *map_type_name(__u32 type)
{
	switch (type) {
	case BPF_MAP_TYPE_ARRAY:
		return "array";
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		return "percpu_array";
	case BPF_MAP_TYPE_HASH:
		return "hash";
	case BPF_MAP_TYPE_PERCPU_HASH:
		return "percpu_hash";
	case BPF_MAP_TYPE_LRU_HASH:
		return "lru_hash";
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
		return "lru_percpu_hash";
	case BPF_MAP_TYPE_RINGBUF:
		return "ringbuf";
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		return "perf_event_array";
	case BPF_MAP_TYPE_STACK_TRACE:
		return "stack_trace";
	case BPF_MAP_TYPE_PROG_ARRAY:
		return "prog_array";
	case BPF_MAP_TYPE_ARENA:
		return "arena";
	default:
		return "unknown";
	}
}

static inline const char *map_skip_reason(__u32 type)
{
	switch (type) {
	case BPF_MAP_TYPE_RINGBUF:
		return "use `shirudo upatch events`";
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		return "perf-event-array: use `shirudo upatch perfbuf` "
		       "(future work)";
	case BPF_MAP_TYPE_STACK_TRACE:
		return "stack-trace: use `shirudo upatch stacktrace` "
		       "(future work)";
	case BPF_MAP_TYPE_PROG_ARRAY:
		return "prog-array carries function pointers; not dumpable";
	case BPF_MAP_TYPE_ARENA:
		return "arena map contents require a serializer";
	default:
		return NULL;
	}
}

#endif /* SHIRUDO_UTIL_UPATCH_MAP_TYPES_H */
