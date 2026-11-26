// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What a root task without runtime authority can do with bpf() in shared
 * enforcement, through the raw syscall. "own <pin>" creates, writes and
 * pins a map of its own, loads a socket filter and opens the pin again;
 * "lsm" loads an LSM program; "objects" opens every map and program by
 * id and prints "map|prog <id> <name>" for those it opens and
 * "map|prog <id> errno=<n>" for the others. No libbpf.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

#include <shirudo/misc.h>

static int sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int fail(const char *step)
{
	printf("%s errno=%d\n", step, errno);
	return 1;
}

static const struct bpf_insn return_zero[] = {
	{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0 },
	{ .code = BPF_JMP | BPF_EXIT },
};

static int load(__u32 type, __u32 attach_type, __u32 btf_id)
{
	union bpf_attr attr = {};

	attr.prog_type = type;
	attr.expected_attach_type = attach_type;
	attr.attach_btf_id = btf_id;
	attr.insns = ptr_to_u64(return_zero);
	attr.insn_cnt = ARRAY_SIZE(return_zero);
	attr.license = ptr_to_u64("GPL");
	return sys_bpf(BPF_PROG_LOAD, &attr);
}

static int own(const char *pin)
{
	union bpf_attr attr = {};
	__u64 value = 7;
	__u32 key = 0;
	int map, prog, got;

	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(key);
	attr.value_size = sizeof(value);
	attr.max_entries = 1;
	map = sys_bpf(BPF_MAP_CREATE, &attr);
	if (map < 0)
		return fail("map_create");

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map;
	attr.key = ptr_to_u64(&key);
	attr.value = ptr_to_u64(&value);
	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr))
		return fail("map_update");

	prog = load(BPF_PROG_TYPE_SOCKET_FILTER, 0, 0);
	if (prog < 0)
		return fail("prog_load");

	memset(&attr, 0, sizeof(attr));
	attr.pathname = ptr_to_u64(pin);
	attr.bpf_fd = map;
	if (sys_bpf(BPF_OBJ_PIN, &attr))
		return fail("obj_pin");
	memset(&attr, 0, sizeof(attr));
	attr.pathname = ptr_to_u64(pin);
	got = sys_bpf(BPF_OBJ_GET, &attr);
	unlink(pin);
	if (got < 0)
		return fail("obj_get");
	printf("ok\n");
	return 0;
}

static int lsm(void)
{
	/* The hook refuses the type before the verifier resolves the id. */
	if (load(BPF_PROG_TYPE_LSM, BPF_LSM_MAC, 1) < 0)
		return fail("lsm_load");
	printf("ok\n");
	return 0;
}

static void object_name(int fd, bool is_map, char name[BPF_OBJ_NAME_LEN])
{
	struct bpf_prog_info prog = {};
	struct bpf_map_info map = {};
	union bpf_attr attr = {};

	attr.info.bpf_fd = fd;
	attr.info.info_len = is_map ? sizeof(map) : sizeof(prog);
	attr.info.info = is_map ? ptr_to_u64(&map) : ptr_to_u64(&prog);
	name[0] = 0;
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr))
		return;
	memcpy(name, is_map ? map.name : prog.name, BPF_OBJ_NAME_LEN);
	name[BPF_OBJ_NAME_LEN - 1] = 0;
}

static void walk(bool is_map)
{
	const char *kind = is_map ? "map" : "prog";
	char name[BPF_OBJ_NAME_LEN];
	union bpf_attr attr = {};
	__u32 id = 0;
	int fd;

	for (;;) {
		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (sys_bpf(is_map ? BPF_MAP_GET_NEXT_ID : BPF_PROG_GET_NEXT_ID,
			    &attr))
			return;
		id = attr.next_id;
		memset(&attr, 0, sizeof(attr));
		if (is_map)
			attr.map_id = id;
		else
			attr.prog_id = id;
		fd = sys_bpf(is_map ? BPF_MAP_GET_FD_BY_ID :
				      BPF_PROG_GET_FD_BY_ID, &attr);
		if (fd < 0) {
			printf("%s %u errno=%d\n", kind, id, errno);
			continue;
		}
		object_name(fd, is_map, name);
		printf("%s %u %s\n", kind, id, name[0] ? name : "-");
		close(fd);
	}
}

int main(int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "own"))
		return own(argv[2]);
	if (argc == 2 && !strcmp(argv[1], "lsm"))
		return lsm();
	if (argc == 2 && !strcmp(argv[1], "objects")) {
		walk(true);
		walk(false);
		return 0;
	}
	fprintf(stderr, "usage: %s own <pin> | lsm | objects\n", argv[0]);
	return 2;
}
