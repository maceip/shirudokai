// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Harness for upatch map type naming / generic-read policy. This stays
 * offline so the arena policy can be tested without root or pinned maps.
 */

#include <stdio.h>
#include <string.h>

#include "upatch_map_types.h"

int main(int argc, char **argv)
{
	const char *s;

	if (argc != 2)
		return 2;

	if (strcmp(argv[1], "arena-name") == 0) {
		puts(map_type_name(BPF_MAP_TYPE_ARENA));
		return 0;
	}
	if (strcmp(argv[1], "arena-skip") == 0) {
		s = map_skip_reason(BPF_MAP_TYPE_ARENA);
		puts(s ? s : "");
		return 0;
	}
	if (strcmp(argv[1], "array-skip") == 0) {
		s = map_skip_reason(BPF_MAP_TYPE_ARRAY);
		puts(s ? s : "");
		return 0;
	}
	if (strcmp(argv[1], "ringbuf-name") == 0) {
		puts(map_type_name(BPF_MAP_TYPE_RINGBUF));
		return 0;
	}
	if (strcmp(argv[1], "ringbuf-skip") == 0) {
		s = map_skip_reason(BPF_MAP_TYPE_RINGBUF);
		puts(s ? s : "");
		return 0;
	}
	return 2;
}
