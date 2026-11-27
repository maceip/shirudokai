// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo-quote-check: rows of keepalive quotes on standard input, one
 * JSON verdict per row on standard output, for as long as rows come.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "help.h"
#include "io.h"
#include "malloc.h"
#include "options.h"
#include "row.h"

enum quote_check_opt {
	QUOTE_CHECK_OTEL,
};

static const struct opt_spec quote_check_opts[] = {
	[QUOTE_CHECK_OTEL] = { "--otel", 0, 0, NULL,
		"verify origin-signed OTLP telemetry envelopes" },
};

static const struct help_section quote_check_sections[] = {
	HELP_OPTIONS("options:", quote_check_opts),
};

static const struct help quote_check_help = {
	.usage	 = "shirudo-quote-check [--otel]",
	.summary = "Reads TabSeparated rows from standard input until it ends:\n"
		   "  <attest>\\t<sig>\\t<ak>\\t<body_sha256>\n"
		   "or with --otel:\n"
		   "  <ak_name>\\t<attest>\\t<sig>\\t<ak>\\t<body_sha256>\n"
		   "attest, sig and ak are a keepalive quote's TPMS_ATTEST and\n"
		   "TPMT_SIGNATURE and the signing key's TPMT_PUBLIC, in standard\n"
		   "base64 (all hex with --otel).\n"
		   "body_sha256 is the SHA-256 of the record's body, 64\n"
		   "hex digits. Writes one JSON line per row, in order:\n"
		   "  {\"ok\":1,\"ak_name\":\"<hex>\",\"ak_public\":\"<base64>\",\n"
		   "   \"reset_count\":<n>,\"restart_count\":<n>,\"clock\":<n>}\n"
		   "  {\"ok\":0,\"reason\":\"bad_signature\"|\"body_mismatch\"|\n"
		   "   \"malformed\"}",
	.sections   = quote_check_sections,
	.n_sections = ARRAY_SIZE(quote_check_sections),
};

/* got is what read_text_line() returned for line, never 0. */
static int line_check(const char *line, int got, bool otel,
		      struct quote_result *res)
{
	size_t len;

	/* A NUL in the line, or more bytes than the longest row has. */
	if (got == -EINVAL || got == -E2BIG) {
		*res = (struct quote_result){ .verdict = QUOTE_MALFORMED };
		return 0;
	}
	if (got < 0)
		return got;
	len = strlen(line);
	if (len && line[len - 1] == '\n')
		len--;
	return otel ? quote_otel_row_check(line, len, res) :
		      quote_row_check(line, len, res);
}

static int verdict_write(const struct quote_result *res)
{
	char json[QUOTE_LINE_MAX];
	int ret;

	ret = quote_row_emit(res, json, sizeof(json));
	if (ret)
		return ret;
	/* The caller waits for each row's answer before it sends the next. */
	if (puts(json) == EOF || fflush(stdout) == EOF)
		return -EIO;
	return 0;
}

int main(int argc, char **argv)
{
	struct quote_result res;
	char *line = NULL;
	bool otel = false;
	struct opt_parser p;
	size_t cap = 0, row_max;
	int got, ret = 0, opt;

	OPT_INIT(&p, "shirudo-quote-check", quote_check_opts,
		 &quote_check_help, argc, (const char **)argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case QUOTE_CHECK_OTEL:
			otel = true;
			break;
		case OPT_ARG:
			opt_usage(&p, "takes no argument, got '%s'", p.value);
			return EXIT_USAGE;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}

	row_max = otel ? QUOTE_OTEL_ROW_MAX : QUOTE_ROW_MAX;
	do {
		got = read_text_line(stdin, &line, &cap, row_max);
		if (!got)
			break;
		ret = line_check(line, got, otel, &res);
		if (!ret)
			ret = verdict_write(&res);
	} while (!ret);
	libc_free(line);
	if (ret) {
		fprintf(stderr, "shirudo-quote-check: %s\n", strerror(-ret));
		return 1;
	}
	return 0;
}
