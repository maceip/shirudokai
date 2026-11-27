// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * `shirudo-build keys vouch` and `keys rotate`: sign vouches and rotate
 * ML-DSA-87 operator signing keys with a bounded vouch from the retiring key.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "util/crypto.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/options.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/sign.h"

#define VOUCH_SIG_MAX			(64u * 1024u)
#define VOUCH_EXPIRES_DAYS_MAX		36500ULL
#define ROTATE_DEFAULT_EXPIRES_DAYS	90ULL
#define CERT_CN				"shirudo"
#define CERT_NO_EXPIRY			"99991231235959Z"
#define GENKEY_ALG			"ML-DSA-87"

enum vouch_opt {
	VOUCH_OUTPUT,
	VOUCH_KEYS_DIR,
	VOUCH_KEY,
	VOUCH_CERT,
	VOUCH_EXPIRES_DAYS,
};

static const struct opt_spec vouch_opts[] = {
	[VOUCH_OUTPUT] = { "--output", 'o', 0, "<file>",
		"where to write the vouch (default <cert.der>.vouch)" },
	[VOUCH_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>" },
	[VOUCH_KEY] = { "--key", 0, 0, "<signing_key.pem>",
		"the signing key (overrides --keys-dir)" },
	[VOUCH_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the signing certificate (overrides --keys-dir)" },
	[VOUCH_EXPIRES_DAYS] = { "--expires-days", 0, 0, "<n>",
		"bound the vouch to expire <n> days from now" },
};

static const struct help_section vouch_sections[] = {
	HELP_OPTIONS("options:", vouch_opts),
};

static const struct help vouch_help = {
	.usage	    = "shirudo keys vouch <cert.der> [-o <file>] "
		      "[--keys-dir <dir>]\n"
		      "                          [--key <signing_key.pem>] "
		      "[--cert <cert.der>] [--expires-days <n>]",
	.summary    = "Sign a vouch for another operator's certificate with "
		      "this operator's key,\nfor `shirudo keys add --vouch` or "
		      "a signed config image's trusted set.\nPrints the vouched "
		      "certificate's fingerprint.",
	.sections   = vouch_sections,
	.n_sections = ARRAY_SIZE(vouch_sections),
};

enum rotate_opt {
	ROTATE_OLD_KEYS_DIR,
	ROTATE_KEYS_DIR,
	ROTATE_EXPIRES_DAYS,
};

static const struct opt_spec rotate_opts[] = {
	[ROTATE_OLD_KEYS_DIR] = { "--old-keys-dir", 0, 0, "<dir>",
		"directory holding the retiring signing_key.pem and cert.der" },
	[ROTATE_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"new directory for the replacement keypair and vouch" },
	[ROTATE_EXPIRES_DAYS] = { "--expires-days", 0, 0, "<n>",
		"vouch expiration window in days (default 90)" },
};

static const struct help_section rotate_sections[] = {
	HELP_OPTIONS("options:", rotate_opts),
};

static const struct help rotate_help = {
	.usage	    = "shirudo keys rotate --old-keys-dir <dir> "
		      "--keys-dir <new-dir> [--expires-days <n>]",
	.summary    = "Generate a new ML-DSA-87 signing keypair and X.509 "
		      "certificate under\n<new-dir> and sign a bounded vouch "
		      "for it with the retiring key in <dir>.\nPrints the new "
		      "certificate's fingerprint.",
	.sections   = rotate_sections,
	.n_sections = ARRAY_SIZE(rotate_sections),
};

static int cert_algorithm_and_time_ok(const __u8 *der, size_t der_sz,
				      __s64 unix_sec, const char *what)
{
	struct cert cert = {};
	char name[64] = {};
	int ret, valid;

	ret = cert_read_der(der, der_sz, &cert);
	if (ret) {
		pr_err("%s is not a certificate", what);
		return ret;
	}
	valid = cert_valid_at(&cert, unix_sec);
	ret = cert_key_algorithm(&cert, name, sizeof(name));
	cert_free(&cert);
	if (valid) {
		pr_err("%s is outside its validity period", what);
		return valid;
	}
	if (ret || strcmp(name, GENKEY_ALG)) {
		pr_err("%s is %s; shirudo accepts only %s", what,
		       ret ? "of an unknown algorithm" : name, GENKEY_ALG);
		return -EKEYREJECTED;
	}
	return 0;
}

static int write_vouch_file(const char *path, const void *data, size_t len)
{
	return seal_write_file_mode(path, data, len, 0644);
}

static int sign_and_write_vouch(const char *pkey, const char *cert,
				const __u8 *der, size_t der_sz,
				__u64 expires_days, __s64 now,
				const char *output)
{
	__u8 *payload = NULL, *encoded = NULL;
	size_t payload_sz = 0, encoded_sz = 0;
	struct sign_io io = {};
	__s64 not_after = 0;
	int ret;

	if (expires_days) {
		not_after = now + (__s64)(expires_days * 86400ULL);
		ret = keys_vouch_payload_v2(der, der_sz, not_after, &payload,
					    &payload_sz);
	} else {
		ret = keys_vouch_payload(der, der_sz, &payload, &payload_sz);
	}
	if (ret)
		return ret;
	io.insns = payload;
	io.insns_sz = payload_sz;
	io.signature_sz = VOUCH_SIG_MAX;
	io.signature = xmalloc(VOUCH_SIG_MAX);
	if (!io.signature) {
		xfree(payload, payload_sz);
		return -ENOMEM;
	}
	ret = cms_sign(&io, pkey, cert);
	if (ret) {
		pr_err("keys vouch: sign: %s", strerror(-ret));
		goto out;
	}
	if (expires_days) {
		ret = keys_vouch_encode_v2(not_after, io.signature,
					   io.signature_sz, &encoded,
					   &encoded_sz);
		if (!ret)
			ret = write_vouch_file(output, encoded, encoded_sz);
		xfree(encoded, encoded_sz);
	} else {
		ret = write_vouch_file(output, io.signature, io.signature_sz);
	}
	if (ret)
		pr_err("keys vouch: write %s: %s", output, strerror(-ret));
out:
	xfree(io.signature, VOUCH_SIG_MAX);
	xfree(payload, payload_sz);
	return ret;
}

int build_keys_vouch(int argc, const char **argv)
{
	const char *pkey = SIGNING_KEY_PATH, *cert = CERT_PATH;
	const char *keys_dir_arg = NULL, *input = NULL, *output = NULL;
	__u8 *der = NULL, *own = NULL;
	size_t der_sz = 0, own_sz = 0;
	__u8 sha[32], fp[32], own_fp[32];
	int pkey_explicit = 0, cert_explicit = 0;
	char fp_hex[65], own_hex[65];
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	char revoked_dir[PATH_MAX];
	char out_path[PATH_MAX];
	__u64 expires_days = 0;
	struct opt_parser p;
	const char *keys_dir;
	int ret = 1, opt;
	__s64 now;

	OPT_INIT(&p, "keys vouch", vouch_opts, &vouch_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case VOUCH_OUTPUT:
			output = p.value;
			break;
		case VOUCH_KEYS_DIR:
			keys_dir_arg = p.value;
			break;
		case VOUCH_KEY:
			pkey = p.value;
			pkey_explicit = 1;
			break;
		case VOUCH_CERT:
			cert = p.value;
			cert_explicit = 1;
			break;
		case VOUCH_EXPIRES_DAYS:
			if (opt_u64(&p, 1, VOUCH_EXPIRES_DAYS_MAX,
				    &expires_days))
				return EXIT_USAGE;
			break;
		case OPT_ARG:
			if (input) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			input = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!input) {
		opt_usage(&p, "takes <cert.der>");
		return EXIT_USAGE;
	}
	keys_dir = keys_dir_resolve(keys_dir_arg);
	revoked_dir[0] = '\0';
	if (keys_dir) {
		if (!pkey_explicit) {
			if (format_key_path(pkey_path, sizeof(pkey_path),
					    keys_dir, SIGNING_KEY_FILE)) {
				pr_err("invalid keys dir %s", keys_dir);
				return 2;
			}
			pkey = pkey_path;
		}
		if (!cert_explicit) {
			if (format_key_path(cert_path, sizeof(cert_path),
					    keys_dir, CERT_FILE)) {
				pr_err("invalid keys dir %s", keys_dir);
				return 2;
			}
			cert = cert_path;
		}
		if (!cert_explicit &&
		    strsprintf(revoked_dir, sizeof(revoked_dir), "%s/revoked",
			       keys_dir) < 0) {
			pr_err("invalid keys dir %s", keys_dir);
			return 2;
		}
	}
	if (build_check_keys(pkey, cert))
		return 1;
	if (!output) {
		if (strsprintf(out_path, sizeof(out_path), "%s.vouch",
			       input) < 0) {
			pr_err("keys vouch: output path too long");
			return 2;
		}
		output = out_path;
	}

	now = (__s64)time(NULL);
	ret = keys_read_der(input, &der, &der_sz);
	if (ret) {
		pr_err("keys vouch: read %s: %s", input, strerror(-ret));
		return 1;
	}
	ret = keys_digest_der(der, der_sz, sha, fp);
	if (ret) {
		pr_err("keys vouch: %s is not a certificate", input);
		goto out;
	}
	ret = cert_algorithm_and_time_ok(der, der_sz, now, input);
	if (ret)
		goto out;
	ret = keys_read_der(cert, &own, &own_sz);
	if (ret) {
		pr_err("keys vouch: read %s: %s", cert, strerror(-ret));
		goto out;
	}
	ret = keys_digest_der(own, own_sz, sha, own_fp);
	if (ret) {
		pr_err("keys vouch: %s is not a certificate", cert);
		goto out;
	}
	ret = cert_algorithm_and_time_ok(own, own_sz, now, cert);
	if (ret)
		goto out;
	hex_encode(fp, 32, fp_hex);
	hex_encode(own_fp, 32, own_hex);
	if (!memcmp(fp, own_fp, 32)) {
		pr_err("keys vouch: %s holds the signing key itself; a key "
		       "cannot vouch for its own certificate", input);
		ret = -EINVAL;
		goto out;
	}
	if (revoked_dir[0] && keys_is_revoked(revoked_dir, own_fp)) {
		pr_err("keys vouch: signing certificate %s is revoked under %s",
		       own_hex, revoked_dir);
		ret = -EKEYREVOKED;
		goto out;
	}
	ret = sign_and_write_vouch(pkey, cert, der, der_sz, expires_days, now,
				   output);
	if (ret)
		goto out;
	pr_info("keys vouch: %s vouched for by %s, written to %s", fp_hex,
		own_hex, output);
	printf("%s\n", fp_hex);
out:
	xfree(own, own_sz);
	xfree(der, der_sz);
	return ret ? 1 : 0;
}

static int add_cert_ext(X509 *c, int nid, const char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	int ret;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, c, c, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		openssl_complain("X509V3_EXT_conf_nid");
		return -1;
	}
	ret = X509_add_ext(c, ex, -1);
	X509_EXTENSION_free(ex);
	if (ret != 1) {
		openssl_complain("X509_add_ext");
		return -1;
	}
	return 0;
}

static int build_rotate_cert(X509 *c, EVP_PKEY *pkey)
{
	X509_NAME *name = X509_NAME_new();
	int ret = -1;

	if (!name) {
		openssl_complain("X509_NAME_new");
		return -1;
	}
	if (X509_set_version(c, 2) != 1 ||
	    ASN1_INTEGER_set(X509_get_serialNumber(c), 1) != 1 ||
	    !X509_gmtime_adj(X509_getm_notBefore(c), 0) ||
	    ASN1_TIME_set_string_X509(X509_getm_notAfter(c),
				      CERT_NO_EXPIRY) != 1 ||
	    X509_set_pubkey(c, pkey) != 1 ||
	    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
				       (const __u8 *)CERT_CN, -1, -1, 0) != 1 ||
	    X509_set_subject_name(c, name) != 1 ||
	    X509_set_issuer_name(c, name) != 1 ||
	    add_cert_ext(c, NID_basic_constraints, "critical,CA:FALSE") != 0 ||
	    add_cert_ext(c, NID_key_usage, "digitalSignature") != 0 ||
	    add_cert_ext(c, NID_subject_key_identifier, "hash") != 0 ||
	    add_cert_ext(c, NID_authority_key_identifier, "keyid:always") != 0 ||
	    X509_sign(c, pkey, NULL) == 0) {
		openssl_complain("build_rotate_cert");
		goto out;
	}
	ret = 0;
out:
	X509_NAME_free(name);
	return ret;
}

static int write_rotate_key(EVP_PKEY *pkey, const char *path)
{
	int fd, ret = -1;
	BIO *b = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_err("keys rotate: open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0)
		goto out;
	b = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!b ||
	    PEM_write_bio_PrivateKey(b, pkey, NULL, NULL, 0, NULL, NULL) != 1 ||
	    fsync(fd) != 0)
		goto out;
	ret = 0;
out:
	BIO_free(b);
	close(fd);
	if (ret != 0)
		unlink(path);
	return ret;
}

static int write_rotate_cert(X509 *c, const char *path)
{
	int fd, ret = -1;
	BIO *bio = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_err("keys rotate: open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0)
		goto out;
	bio = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!bio || i2d_X509_bio(bio, c) != 1 || fsync(fd) != 0)
		goto out;
	ret = 0;
out:
	BIO_free(bio);
	close(fd);
	if (ret != 0)
		unlink(path);
	return ret;
}

int build_keys_rotate(int argc, const char **argv)
{
	__u64 expires_days = ROTATE_DEFAULT_EXPIRES_DAYS;
	const char *old_dir = NULL, *new_dir = NULL;
	char old_pkey[PATH_MAX], old_cert[PATH_MAX], old_revoked[PATH_MAX];
	char new_pkey[PATH_MAX], new_cert[PATH_MAX], vouch_path[PATH_MAX];
	__u8 *old_der = NULL, *new_der = NULL;
	size_t old_sz = 0, new_sz = 0;
	__u8 sha[32], old_fp[32], new_fp[32];
	char old_hex[65], new_hex[65];
	EVP_PKEY *pkey = NULL;
	int ret = 1, opt, dfd = -1;
	X509 *cert = NULL;
	struct opt_parser p;
	__s64 now;

	OPT_INIT(&p, "keys rotate", rotate_opts, &rotate_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case ROTATE_OLD_KEYS_DIR:
			old_dir = p.value;
			break;
		case ROTATE_KEYS_DIR:
			new_dir = p.value;
			break;
		case ROTATE_EXPIRES_DAYS:
			if (opt_u64(&p, 1, VOUCH_EXPIRES_DAYS_MAX,
				    &expires_days))
				return EXIT_USAGE;
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
	if (!old_dir || !new_dir) {
		opt_usage(&p, "--old-keys-dir and --keys-dir are required");
		return EXIT_USAGE;
	}
	if (!strcmp(old_dir, new_dir) || !strcmp(new_dir, "/")) {
		pr_err("keys rotate: --keys-dir must name a distinct directory");
		return EXIT_USAGE;
	}
	if (key_paths(old_dir, old_pkey, sizeof(old_pkey), old_cert,
		      sizeof(old_cert)) ||
	    strsprintf(old_revoked, sizeof(old_revoked), "%s/revoked",
		       old_dir) < 0 ||
	    key_paths(new_dir, new_pkey, sizeof(new_pkey), new_cert,
		      sizeof(new_cert)) ||
	    strsprintf(vouch_path, sizeof(vouch_path), "%s.vouch",
		       new_cert) < 0) {
		pr_err("keys rotate: keys directory path too long");
		return EXIT_USAGE;
	}
	if (build_check_keys(old_pkey, old_cert))
		return 1;
	if (path_exists(new_pkey) || path_exists(new_cert) ||
	    path_exists(vouch_path)) {
		pr_err("keys rotate: %s already holds key material", new_dir);
		return 1;
	}

	now = (__s64)time(NULL);
	ret = keys_read_der(old_cert, &old_der, &old_sz);
	if (ret) {
		pr_err("keys rotate: read %s: %s", old_cert, strerror(-ret));
		return 1;
	}
	ret = keys_digest_der(old_der, old_sz, sha, old_fp);
	if (ret) {
		pr_err("keys rotate: %s is not a certificate", old_cert);
		goto out;
	}
	ret = cert_algorithm_and_time_ok(old_der, old_sz, now, old_cert);
	if (ret)
		goto out;
	hex_encode(old_fp, 32, old_hex);
	if (keys_is_revoked(old_revoked, old_fp)) {
		pr_err("keys rotate: retiring certificate %s is revoked",
		       old_hex);
		ret = -EKEYREVOKED;
		goto out;
	}

	ret = seal_mkdir_p(new_dir, 0700);
	if (ret) {
		pr_err("keys rotate: mkdir %s: %s", new_dir, strerror(-ret));
		goto out;
	}
	dfd = open(new_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (dfd < 0) {
		ret = -errno;
		pr_err("keys rotate: open %s: %s", new_dir, strerror(-ret));
		goto out;
	}
	if (fchmod(dfd, 0700) != 0) {
		ret = -errno;
		pr_err("keys rotate: chmod %s: %s", new_dir, strerror(-ret));
		goto out;
	}
	ret = -EIO;
	pkey = EVP_PKEY_Q_keygen(NULL, NULL, GENKEY_ALG);
	cert = pkey ? X509_new() : NULL;
	if (!pkey || !cert || build_rotate_cert(cert, pkey) != 0)
		goto out;
	if (write_rotate_key(pkey, new_pkey) != 0)
		goto out;
	if (write_rotate_cert(cert, new_cert) != 0) {
		unlink(new_pkey);
		goto out;
	}
	ret = keys_read_der(new_cert, &new_der, &new_sz);
	if (!ret)
		ret = keys_digest_der(new_der, new_sz, sha, new_fp);
	if (!ret)
		ret = sign_and_write_vouch(old_pkey, old_cert, new_der, new_sz,
					   expires_days, now, vouch_path);
	if (!ret && fsync(dfd) != 0) {
		ret = -errno;
		pr_err("keys rotate: fsync %s: %s", new_dir, strerror(-ret));
	}
	if (ret) {
		unlink(new_pkey);
		unlink(new_cert);
		unlink(vouch_path);
		goto out;
	}
	hex_encode(new_fp, 32, new_hex);
	pr_audit("keys rotate: new_fingerprint=%s vouched_by=%s expires_days=%llu",
		 new_hex, old_hex, expires_days);
	printf("%s\n", new_hex);
	ret = 0;
out:
	if (dfd >= 0)
		close(dfd);
	X509_free(cert);
	EVP_PKEY_free(pkey);
	xfree(new_der, new_sz);
	xfree(old_der, old_sz);
	return ret ? 1 : 0;
}
