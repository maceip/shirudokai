// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-only `bpm feed`: sign, verify, list and match curated CVE
 * shield feeds offline against enrolled package keys or an explicit
 * certificate override.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "bpm_feed.h"
#include "bpm_package.h"
#include "bpm_tree.h"
#include "help.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "options.h"
#include "paths.h"
#include "sign.h"

int build_bpm_feed(int argc, const char **argv);

static const struct help_item bpm_feed_subcmds[] = {
	{ "verify", "verify a signed curated CVE shield feed" },
	{ "list", "verify and list entries of a curated CVE shield feed" },
	{ "match", "verify and list feed entries matching this host" },
	{ "sign", "sign a curated CVE shield feed with ML-DSA-87" },
};

enum bpm_feed_opt {
	FEED_OPT_FEED,
	FEED_OPT_SIG,
	FEED_OPT_CERT,
	FEED_OPT_KEYS_DIR,
	FEED_OPT_JSON,
	FEED_OPT_CVE,
};

enum bpm_feed_sign_opt {
	FEED_SIGN_FEED,
	FEED_SIGN_OUT,
	FEED_SIGN_KEYS_DIR,
	FEED_SIGN_KEY,
	FEED_SIGN_CERT,
};

static const struct opt_spec bpm_feed_verify_opts[] = {
	[FEED_OPT_FEED] = { "--feed", 0, 0, "<path>", "feed JSON file" },
	[FEED_OPT_SIG] = { "--sig", 0, 0, "<path>",
		"detached ML-DSA-87 CMS signature" },
	[FEED_OPT_CERT] = { "--cert", 0, 0, "<cert.der>",
		"explicit signer certificate override" },
	[FEED_OPT_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"enrolled package keys directory" },
	[FEED_OPT_JSON] = { "--json", 0, 0, NULL, "print verdict as JSON" },
};

static const struct opt_spec bpm_feed_query_opts[] = {
	[FEED_OPT_FEED] = { "--feed", 0, 0, "<path>", "feed JSON file" },
	[FEED_OPT_SIG] = { "--sig", 0, 0, "<path>",
		"detached ML-DSA-87 CMS signature" },
	[FEED_OPT_CERT] = { "--cert", 0, 0, "<cert.der>",
		"explicit signer certificate override" },
	[FEED_OPT_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"enrolled package keys directory" },
	[FEED_OPT_JSON] = { "--json", 0, 0, NULL,
		"print feed entries as JSON" },
	[FEED_OPT_CVE] = { "--cve", 0, 0, "<cve-id>",
		"filter entries fixing this CVE" },
};

static const struct opt_spec bpm_feed_sign_opts[] = {
	[FEED_SIGN_FEED] = { "--feed", 0, 0, "<path>", "feed JSON file" },
	[FEED_SIGN_OUT] = { "--out", 0, 0, "<path>",
		"signature output path (default <feed>.p7s)" },
	[FEED_SIGN_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"keys directory holding signing_key.pem and cert.der" },
	[FEED_SIGN_KEY] = { "--key", 0, 0, "<key.pem>",
		"ML-DSA-87 signing key" },
	[FEED_SIGN_CERT] = { "--cert", 0, 0, "<cert.der>",
		"signer certificate" },
};

static const struct help_section bpm_feed_sections[] = {
	HELP_ITEMS("subcommands:", bpm_feed_subcmds),
	HELP_OPTIONS("verify/list/match options:", bpm_feed_query_opts),
	HELP_OPTIONS("sign options:", bpm_feed_sign_opts),
};

static const struct help bpm_feed_help = {
	.usage	    = "shirudo bpm feed verify --feed <path> --sig <path> "
		      "[--keys-dir <dir> | --cert <cert.der>] [--json]\n"
		      "       shirudo bpm feed list --feed <path> --sig <path> "
		      "[--keys-dir <dir> | --cert <cert.der>] [--cve <CVE-ID>] "
		      "[--json]\n"
		      "       shirudo bpm feed match --feed <path> --sig <path> "
		      "[--keys-dir <dir> | --cert <cert.der>] [--cve <CVE-ID>] "
		      "[--json]\n"
		      "       shirudo bpm feed sign --feed <path> [--out <path>] "
		      "[--keys-dir <dir> | --key <pem> --cert <der>]",
	.summary    = "Sign, verify and query offline ML-DSA-87 signed curated "
		      "CVE shield feeds.",
	.sections   = bpm_feed_sections,
	.n_sections = ARRAY_SIZE(bpm_feed_sections),
};

static int feed_print_verify(const struct bpm_feed *feed, bool cert_override,
			     bool json)
{
	const char *trust = cert_override ? "explicit_cert" : "enrolled_keys";

	if (!json) {
		printf("Verified feed %s (%d entries, generated %s%s%s)\n",
		       feed->feed_id, feed->n_entries, feed->generated_at,
		       feed->expires[0] ? ", expires " : "",
		       feed->expires[0] ? feed->expires : "");
		if (cert_override)
			printf("Trust: explicit --cert override\n");
		return 0;
	}
	{
		char buf[1024];
		struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_kv_bool(&e, "verified", 1);
		json_kv_string(&e, "trust", trust);
		json_kv_string(&e, "feed_id", feed->feed_id);
		json_kv_string(&e, "generated_at", feed->generated_at);
		if (feed->expires[0])
			json_kv_string(&e, "expires", feed->expires);
		json_kv_int(&e, "entries", feed->n_entries);
		json_obj_close(&e);
		if (e.err)
			return e.err;
		puts(buf);
	}
	return 0;
}

static void feed_print_table(const struct bpm_feed *feed, const bool *keep,
			     int n_kept)
{
	size_t id_w = 8, pkg_w = 8;

	for (int i = 0; i < feed->n_entries; i++) {
		if (!keep[i])
			continue;
		id_w = max(id_w, strlen(feed->entries[i].id));
		pkg_w = max(pkg_w, strlen(feed->entries[i].package));
	}
	printf("Feed %s (%d matching):\n", feed->feed_id, n_kept);
	if (!n_kept) {
		printf("  none\n");
		return;
	}
	printf("  %-*s  %-10s  %-*s  %-12s  %s\n", (int)id_w, "ID", "ROLE",
	       (int)pkg_w, "PACKAGE", "VERSION", "CVES");
	for (int i = 0; i < feed->n_entries; i++) {
		const struct bpm_feed_entry *ent = &feed->entries[i];

		if (!keep[i])
			continue;
		printf("  %-*s  %-10s  %-*s  %-12s  ", (int)id_w, ent->id,
		       bpm_feed_role_str(ent->role), (int)pkg_w, ent->package,
		       ent->version);
		for (int j = 0; j < ent->n_cves; j++)
			printf("%s%s", j ? "," : "", ent->cves[j]);
		putchar('\n');
	}
}

static int feed_print_filtered(const struct bpm_feed *feed, const bool *keep,
			       int n_kept, bool json)
{
	struct bpm_feed sub = {};
	size_t out_len = 0;
	char *out = NULL;
	int at = 0, ret;

	if (!json) {
		feed_print_table(feed, keep, n_kept);
		return 0;
	}
	sub.schema = feed->schema;
	bpm_copy_string(sub.feed_id, sizeof(sub.feed_id), feed->feed_id);
	bpm_copy_string(sub.generated_at, sizeof(sub.generated_at),
			feed->generated_at);
	if (feed->expires[0])
		bpm_copy_string(sub.expires, sizeof(sub.expires),
				feed->expires);
	if (n_kept) {
		sub.entries = xcalloc((size_t)n_kept, sizeof(*sub.entries));
		if (!sub.entries)
			return -ENOMEM;
		for (int i = 0; i < feed->n_entries; i++) {
			if (keep[i])
				sub.entries[at++] = feed->entries[i];
		}
		sub.n_entries = n_kept;
	}
	ret = bpm_feed_emit(&sub, &out, &out_len);
	if (!ret) {
		puts(out);
		xfree(out, out_len);
	}
	xfree(sub.entries, (size_t)n_kept * sizeof(*sub.entries));
	return ret;
}

static int feed_run_query(const struct bpm_feed *feed, const char *cve,
			  bool match_node, bool json)
{
	bool keep[BPM_FEED_MAX_ENTRIES] = {};
	struct utsname u = {};
	int n_kept = 0;

	if (match_node && uname(&u) != 0)
		return -errno;
	for (int i = 0; i < feed->n_entries; i++) {
		const struct bpm_feed_entry *ent = &feed->entries[i];

		if (cve && !bpm_feed_entry_has_cve(ent, cve))
			continue;
		if (match_node) {
			int matched;

			if (!bpm_feed_entry_matches_release(ent, u.release))
				continue;
			matched = tree_selector_matches(&ent->selector);
			if (matched < 0)
				return matched;
			if (!matched)
				continue;
		}
		keep[i] = true;
		n_kept++;
	}
	return feed_print_filtered(feed, keep, n_kept, json);
}

static int feed_fail(const char *action, int ret)
{
	pr_err("%s: %s", action, strerror(-ret));
	return 1;
}

static int write_signed_file(const char *path, const void *buf, size_t len)
{
	char tmp[PATH_MAX];
	int fd, ret;

	if (strsprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path,
		       (long)getpid()) < 0)
		return -ENAMETOOLONG;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	ret = write_complete(fd, buf, len);
	if (close(fd) < 0 && !ret)
		ret = -errno;
	if (!ret && rename(tmp, path) < 0)
		ret = -errno;
	if (ret)
		unlink(tmp);
	return ret;
}

static int feed_sign_cmd(int argc, const char **argv)
{
	char key_buf[PATH_MAX], cert_buf[PATH_MAX], out_buf[PATH_MAX];
	const char *feed_path = NULL, *out_path = NULL;
	const char *key_path = NULL, *cert_path = NULL, *keys_dir = NULL;
	struct bpm_feed parsed = {};
	struct sign_io sio = {};
	struct opt_parser p;
	__u8 *body = NULL;
	size_t body_len = 0;
	int opt, ret;

	OPT_INIT(&p, "bpm feed sign", bpm_feed_sign_opts, &bpm_feed_help,
		 argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case FEED_SIGN_FEED:
			feed_path = p.value;
			break;
		case FEED_SIGN_OUT:
			out_path = p.value;
			break;
		case FEED_SIGN_KEYS_DIR:
			keys_dir = p.value;
			break;
		case FEED_SIGN_KEY:
			key_path = p.value;
			break;
		case FEED_SIGN_CERT:
			cert_path = p.value;
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
	if (!feed_path) {
		opt_usage(&p, "takes --feed");
		return EXIT_USAGE;
	}
	if ((key_path && !cert_path) || (!key_path && cert_path)) {
		opt_usage(&p, "--key and --cert must be given together");
		return EXIT_USAGE;
	}
	if (key_path && keys_dir) {
		opt_usage(&p, "pass --keys-dir or --key/--cert, not both");
		return EXIT_USAGE;
	}
	if (!key_path) {
		if (!keys_dir) {
			const char *env = getenv(KEYS_DIR_ENV);

			keys_dir = (env && env[0]) ? env : KEYS_DIR;
		}
		if (strsprintf(key_buf, sizeof(key_buf), "%s/signing_key.pem",
			       keys_dir) < 0 ||
		    strsprintf(cert_buf, sizeof(cert_buf), "%s/cert.der",
			       keys_dir) < 0)
			return feed_fail("bpm feed sign", -ENAMETOOLONG);
		key_path = key_buf;
		cert_path = cert_buf;
	}
	if (!out_path) {
		if (strsprintf(out_buf, sizeof(out_buf), "%s.p7s",
			       feed_path) < 0)
			return feed_fail("bpm feed sign", -ENAMETOOLONG);
		out_path = out_buf;
	}
	ret = read_file(feed_path, JSON_MAX_BYTES, &body, &body_len);
	if (ret)
		return feed_fail("bpm feed sign", ret);
	ret = bpm_feed_parse((const char *)body, body_len, &parsed);
	bpm_feed_free(&parsed);
	if (ret) {
		xfree(body, body_len + 1);
		return feed_fail("bpm feed sign", ret);
	}
	sio.signature_sz = 16384;
	sio.signature = xmalloc(sio.signature_sz);
	if (!sio.signature) {
		xfree(body, body_len + 1);
		return feed_fail("bpm feed sign", -ENOMEM);
	}
	sio.insns = body;
	sio.insns_sz = body_len;
	ret = cms_sign(&sio, key_path, cert_path);
	if (!ret)
		ret = write_signed_file(out_path, sio.signature,
					sio.signature_sz);
	xfree(sio.signature, 16384);
	xfree(body, body_len + 1);
	return ret ? feed_fail("bpm feed sign", ret) : 0;
}

int build_bpm_feed(int argc, const char **argv)
{
	const char *feed_path = NULL, *sig_path = NULL, *cert_path = NULL;
	const char *keys_dir = NULL, *cve = NULL;
	struct bpm_feed feed = {};
	const char *sub, *action;
	struct opt_parser p;
	bool is_verify, json = false;
	int opt, ret;

	if (argc < 2 || is_help(argv[1])) {
		print_help(&bpm_feed_help);
		return argc < 2 ? EXIT_USAGE : 0;
	}
	if (is_list_cmds(argv[1])) {
		print_subcmd_list(bpm_feed_subcmds,
				  ARRAY_SIZE(bpm_feed_subcmds));
		return 0;
	}
	sub = argv[1];
	if (!strcmp(sub, "sign"))
		return feed_sign_cmd(argc - 1, argv + 1);
	if (strcmp(sub, "verify") && strcmp(sub, "list") &&
	    strcmp(sub, "match")) {
		pr_err("bpm feed: '%s' is not a subcommand", sub);
		return EXIT_USAGE;
	}
	is_verify = !strcmp(sub, "verify");
	action = is_verify ? "bpm feed verify" :
		 !strcmp(sub, "list") ? "bpm feed list" : "bpm feed match";
	opt_init(&p, action,
		 is_verify ? bpm_feed_verify_opts : bpm_feed_query_opts,
		 is_verify ? ARRAY_SIZE(bpm_feed_verify_opts) :
			     ARRAY_SIZE(bpm_feed_query_opts),
		 &bpm_feed_help, argc, argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case FEED_OPT_FEED:
			feed_path = p.value;
			break;
		case FEED_OPT_SIG:
			sig_path = p.value;
			break;
		case FEED_OPT_CERT:
			cert_path = p.value;
			break;
		case FEED_OPT_KEYS_DIR:
			keys_dir = p.value;
			break;
		case FEED_OPT_JSON:
			json = true;
			break;
		case FEED_OPT_CVE:
			cve = p.value;
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
	if (!feed_path || !sig_path) {
		opt_usage(&p, "takes --feed and --sig");
		return EXIT_USAGE;
	}
	if (cert_path && keys_dir) {
		opt_usage(&p, "pass --keys-dir or --cert, not both");
		return EXIT_USAGE;
	}
	if (cve && !bpm_feed_cve_ok(cve)) {
		opt_usage(&p, "invalid CVE identifier '%s'", cve);
		return EXIT_USAGE;
	}
	if (cert_path)
		ret = bpm_feed_verify_files(feed_path, sig_path, cert_path,
					    &feed);
	else
		ret = bpm_feed_verify_files_trusted(feed_path, sig_path,
						    keys_dir, &feed);
	if (!ret) {
		if (is_verify)
			ret = feed_print_verify(&feed, cert_path != NULL, json);
		else
			ret = feed_run_query(&feed, cve, !strcmp(sub, "match"),
					     json);
	}
	bpm_feed_free(&feed);
	return ret ? feed_fail(action, ret) : 0;
}
