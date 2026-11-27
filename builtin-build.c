// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Sole exec site in the core shirudo binary: dispatch to the
 * operator-only shirudo-build helper.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "builtin.h"
#include "util/help.h"
#include "util/log.h"
#include "util/malloc.h"

#ifndef LIBEXEC_DIR
#define LIBEXEC_DIR	"/usr/local/libexec/shirudo"
#endif

static const struct help build_help = {
	.usage   = "shirudo build [--observe] <input.bpf.c|.bpf.o|.jar> [-o <output.upatch>] [options]\n"
		   "       shirudo build --unload <upatch-name> [-o <output.upatch>] [options]",
	.summary = "Build a signed BPF .upatch artifact ready\nfor target-side loading. "
		   "Operator-only: "
		   "dispatches to the separate\nshirudo-build binary. The "
		   "helper is resolved in this order:\n"
		   "SHIRUDO_BUILD, " LIBEXEC_DIR "/shirudo-build, "
		   "then shirudo-build on PATH.\n"
		   "Run the selected helper with --help for the full option list.",
};

/*
 * SHIRUDO_BUILD (possibly empty, which the callers reject), the
 * compiled-in libexec path, then a bare name for PATH lookup.
 */
static const char *resolve_helper(bool *use_path)
{
	const char *override = getenv("SHIRUDO_BUILD");
	const char *installed = LIBEXEC_DIR "/shirudo-build";

	*use_path = false;
	if (override)
		return override;
	if (access(installed, X_OK) == 0)
		return installed;
	*use_path = true;
	return "shirudo-build";
}

static bool on_path(const char *name)
{
	const char *path = getenv("PATH");

	while (path && *path) {
		const char *end = strchr(path, ':');
		char candidate[PATH_MAX];
		size_t len;

		if (!end)
			end = path + strlen(path);
		len = (size_t)(end - path);
		if (len && len + 1 < sizeof(candidate)) {
			memcpy(candidate, path, len);
			candidate[len] = '/';
			if (strscpy(candidate + len + 1, name,
				    sizeof(candidate) - len - 1) >= 0 &&
			    access(candidate, X_OK) == 0)
				return true;
		}
		path = *end ? end + 1 : end;
	}
	return false;
}

bool build_available(void)
{
	bool use_path;
	const char *helper = resolve_helper(&use_path);

	if (!*helper)
		return false;
	return use_path ? on_path(helper) : access(helper, X_OK) == 0;
}

int build_exec(const char *label, const char **argv)
{
	bool use_path;
	const char *path = resolve_helper(&use_path);

	if (!*path) {
		pr_err("'%s' cannot use empty SHIRUDO_BUILD", label);
		return 127;
	}
	if (!use_path && access(path, X_OK) != 0) {
		pr_err("'%s' is an operator-only subcommand; "
		       "shirudo-build helper '%s' is not executable. Set "
		       "SHIRUDO_BUILD to a helper path or put shirudo-build on "
		       "PATH.", label, path);
		return 127;
	}
	argv[0] = path;
	if (use_path)
		execvp(path, (char *const *)argv);
	else
		execv(path, (char *const *)argv);
	pr_err("exec %s: %s", path, strerror(errno));
	return 127;
}

int build_forward(const char *label, const char *const words[], int argc,
		  const char **argv)
{
	const char **helper;
	size_t n = 0, count, i;
	int ret;

	while (words[n])
		n++;
	count = n + (size_t)argc + 2;
	helper = xcalloc(count, sizeof(*helper));
	if (!helper) {
		pr_err("'%s': %s", label, strerror(ENOMEM));
		return 1;
	}
	for (i = 0; i < n; i++)
		helper[1 + i] = words[i];
	for (i = 0; i < (size_t)argc; i++)
		helper[1 + n + i] = argv[i];
	ret = build_exec(label, helper);
	xfree(helper, count * sizeof(*helper));
	return ret;
}

int cmd_build(int argc, const char **argv)
{
	if (argc >= 2 && is_help(argv[1])) {
		print_help(&build_help);
		return 0;
	}
	return build_exec("build", argv);
}
