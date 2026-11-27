// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Open and load a compiled BPF object via libbpf to verify that the
 * kernel BPF verifier accepts every program, printing per-program
 * verifier statistics (processed instruction counts).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#define VERIFY_LOG_SIZE (1024 * 1024)

struct prog_log {
	const char	*name;
	char		*buf;
};

static void print_stats_line(const char *name, const char *log)
{
	const char *p = log;
	const char *last = NULL;

	while (p && *p) {
		if (strncmp(p, "processed ", sizeof("processed ") - 1) == 0)
			last = p;
		p = strchr(p, '\n');
		if (p)
			p++;
	}
	if (last) {
		const char *nl = strchr(last, '\n');
		int len = nl ? (int)(nl - last) : (int)strlen(last);

		printf("ok %s: %.*s\n", name, len, last);
	} else {
		printf("ok %s\n", name);
	}
}

int main(int argc, char **argv)
{
	struct prog_log *logs = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	size_t nprogs = 0, i;
	int err, ret = 1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <object.bpf.o>\n",
			argc > 0 ? argv[0] : "test-bpf-verify");
		return 2;
	}

	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "bpf_object__open_file(%s) failed: %s\n",
			argv[1], strerror(errno));
		return 1;
	}

	bpf_object__for_each_program(prog, obj)
		nprogs++;
	if (nprogs) {
		logs = calloc(nprogs, sizeof(*logs));
		if (!logs)
			goto out;
		i = 0;
		bpf_object__for_each_program(prog, obj) {
			logs[i].name = bpf_program__name(prog);
			logs[i].buf = calloc(1, VERIFY_LOG_SIZE);
			if (!logs[i].buf)
				goto out;
			bpf_program__set_log_buf(prog, logs[i].buf,
						 VERIFY_LOG_SIZE);
			bpf_program__set_log_level(prog, 4);
			i++;
		}
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "bpf_object__load(%s) failed: %d (%s)\n",
			argv[1], err, strerror(-err));
		for (i = 0; i < nprogs; i++) {
			if (logs[i].buf && logs[i].buf[0])
				fprintf(stderr, "--- %s ---\n%s\n",
					logs[i].name, logs[i].buf);
		}
		goto out;
	}

	for (i = 0; i < nprogs; i++)
		print_stats_line(logs[i].name, logs[i].buf);
	ret = 0;

out:
	if (logs) {
		for (i = 0; i < nprogs; i++)
			free(logs[i].buf);
		free(logs);
	}
	bpf_object__close(obj);
	return ret;
}
