// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Print release name and SHIRUDO_VERSION_ID.
 */

#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>

#include "builtin.h"
#include "util/crypto.h"
#include "util/help.h"
#include "util/options.h"
#include "util/version.h"

enum version_opt {
	VERSION_ID,
};

static const struct opt_spec version_opts[] = {
	[VERSION_ID] = { "--version-id", 0, 0, NULL,
		"print only the raw SHIRUDO_VERSION_ID, one line" },
};

static const struct help_section version_help_sections[] = {
	HELP_OPTIONS("options:", version_opts),
};

static const struct help version_help = {
	.usage      = "shirudo version [--version-id]",
	.summary    = "Print the release tag plus the architecture-stripped "
		      "SHIRUDO_VERSION_ID\nthat targets compare against the "
		      "operator's signed artifacts.",
	.sections   = version_help_sections,
	.n_sections = ARRAY_SIZE(version_help_sections),
};

int cmd_version(int argc, const char **argv)
{
	bool id_only = false;
	struct opt_parser p;
	int opt;

	OPT_INIT(&p, "version", version_opts, &version_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case VERSION_ID:
			id_only = true;
			break;
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			return EXIT_USAGE;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (id_only) {
		printf("%s\n", shirudo_version_id);
		return 0;
	}
	printf("shirudo (%s%s, \"%s\")\n",
	       shirudo_version, shirudo_extraversion, shirudo_release_name);
	printf("version-id: %s\n", shirudo_version_id);
	printf("fips: %s\n", crypto_fips_enabled() ? "enabled" : "disabled");
	return 0;
}
