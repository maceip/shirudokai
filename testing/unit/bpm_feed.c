// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <shirudo/string.h>

#include "unit.h"

#include "bpm_feed.h"
#include "io.h"
#include "malloc.h"

#define DIGEST_A "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define DIGEST_B "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define DIGEST_UPPER "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"

static void test_cve_ok(void)
{
	EXPECT_TRUE(bpm_feed_cve_ok("CVE-2026-31431"));
	EXPECT_TRUE(bpm_feed_cve_ok("CVE-2025-71093"));
	EXPECT_TRUE(bpm_feed_cve_ok("CVE-2026-109618"));

	EXPECT_FALSE(bpm_feed_cve_ok(NULL));
	EXPECT_FALSE(bpm_feed_cve_ok(""));
	EXPECT_FALSE(bpm_feed_cve_ok("cve-2026-31431"));
	EXPECT_FALSE(bpm_feed_cve_ok("CVE-26-31431"));
	EXPECT_FALSE(bpm_feed_cve_ok("CVE-2026-123"));
	EXPECT_FALSE(bpm_feed_cve_ok("CVE-2026-1234a"));
	EXPECT_FALSE(bpm_feed_cve_ok("CVE-2026-12345678901234567890"));
}

static void test_parse_and_emit_roundtrip(void)
{
	static const char sample[] =
		"{\"schema\":1,\"feed_id\":\"shirudo/shields\","
		"\"generated_at\":\"2026-11-26T12:00:00Z\","
		"\"entries\":["
		"{\"id\":\"cve-2026-31431-alg-splice-block\","
		"\"cves\":[\"CVE-2026-31675\",\"CVE-2026-31431\"],"
		"\"package\":\"cve-2026-31431-alg-splice-block\","
		"\"version\":\"1.0.0\","
		"\"reference\":\"oci://quay.io/shirudo/alg-splice:1.0.0\","
		"\"manifest_digest\":\"" DIGEST_A "\","
		"\"role\":\"mitigation\","
		"\"selector\":{\"architecture\":[\"x86_64\",\"aarch64\"],"
		"\"kconfig\":{\"CONFIG_Z\":[\"y\"],\"CONFIG_A\":[\"y\",\"m\"]},"
		"\"labels\":{\"tier\":[\"prod\"],\"env\":[\"edge\"]}},"
		"\"description\":\"Refuses splice into AF_ALG\"},"
		"{\"id\":\"cve-2025-71093-e1000-tbi-detector\","
		"\"cves\":[\"CVE-2025-71093\"],"
		"\"package\":\"cve-2025-71093-e1000-tbi-detector\","
		"\"version\":\"1.2.3-rc.1\","
		"\"reference\":\"oci://registry.local:5000/shields/e1000@" DIGEST_B "\","
		"\"manifest_digest\":\"" DIGEST_B "\","
		"\"role\":\"detector\","
		"\"selector\":{},"
		"\"description\":\"\"}"
		"]}";
	char *out1 = NULL, *out2 = NULL;
	struct bpm_feed feed, again;
	size_t len1 = 0, len2 = 0;

	ASSERT_EQ(bpm_feed_parse(sample, sizeof(sample) - 1, &feed), 0);
	EXPECT_EQ(feed.schema, 1);
	EXPECT_STREQ(feed.feed_id, "shirudo/shields");
	EXPECT_STREQ(feed.generated_at, "2026-11-26T12:00:00Z");
	ASSERT_EQ(feed.n_entries, 2);

	/* CVEs are sorted canonically on parse/emit. */
	EXPECT_STREQ(feed.entries[0].cves[0], "CVE-2026-31431");
	EXPECT_STREQ(feed.entries[0].cves[1], "CVE-2026-31675");
	EXPECT_EQ(feed.entries[0].role, BPM_FEED_ROLE_MITIGATION);
	EXPECT_TRUE(bpm_feed_entry_has_cve(&feed.entries[0], "CVE-2026-31431"));
	EXPECT_FALSE(bpm_feed_entry_has_cve(&feed.entries[0], "CVE-2025-71093"));
	EXPECT_EQ(feed.entries[1].role, BPM_FEED_ROLE_DETECTOR);

	ASSERT_EQ(bpm_feed_emit(&feed, &out1, &len1), 0);
	ASSERT_EQ(bpm_feed_parse(out1, len1, &again), 0);
	ASSERT_EQ(bpm_feed_emit(&again, &out2, &len2), 0);
	ASSERT_UEQ(len1, len2);
	EXPECT_MEMEQ(out1, out2, len1);

	xfree(out2, len2);
	xfree(out1, len1);
	bpm_feed_free(&again);
	bpm_feed_free(&feed);
}

static void expect_bad(const char *json)
{
	struct bpm_feed feed;

	EXPECT_NE(bpm_feed_parse(json, strlen(json), &feed), 0);
}

static void test_reject_invalid(void)
{
	/* Wrong schema, missing keys, bad feed_id, bad timestamp (Feb 29 2026). */
	expect_bad("{\"schema\":2,\"feed_id\":\"a\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"../bad\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-02-29T00:00:00Z\",\"entries\":[]}");

	/* Leap year Feb 29 2024 is valid. */
	{
		static const char leap[] =
			"{\"schema\":1,\"feed_id\":\"ok\","
			"\"generated_at\":\"2024-02-29T23:59:59Z\","
			"\"entries\":[]}";
		struct bpm_feed feed;

		ASSERT_EQ(bpm_feed_parse(leap, sizeof(leap) - 1, &feed), 0);
		bpm_feed_free(&feed);
	}

	/* Empty cves, duplicate cve, bad role, bad digest, bad reference. */
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\",\"CVE-2026-1111\"],"
		   "\"package\":\"pkg\",\"version\":\"1.0.0\","
		   "\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],"
		   "\"package\":\"pkg\",\"version\":\"1.0.0\","
		   "\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"advisory\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],"
		   "\"package\":\"pkg\",\"version\":\"1.0.0\","
		   "\"reference\":\"https://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],"
		   "\"package\":\"pkg\",\"version\":\"1.0.0\","
		   "\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_UPPER "\","
		   "\"role\":\"mitigation\","
		   "\"selector\":{\"architecture\":[]}}]}");

	/* [null] in scalar arrays (first or second entry) is refused. */
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[null],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\",\"selector\":{\"architecture\":[\"x86_64\"]}},"
		   "{\"id\":\"s2\",\"cves\":[null],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\","
		   "\"selector\":{\"architecture\":[\"x86_64\",null]}}]}");

	/* [""] in selector arrays/maps and "" selector map keys are refused. */
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\","
		   "\"selector\":{\"architecture\":[\"\"]}}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\","
		   "\"selector\":{\"kconfig\":{\"\":[\"y\"]}}}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\","
		   "\"selector\":{\"labels\":{\"env\":[\"\"]}}}]}");

	/* 0x7f (DEL) is refused in text fields and selectors. */
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\",\"description\":\"bad\\u007fchar\"}]}");
	expect_bad("{\"schema\":1,\"feed_id\":\"ok\","
		   "\"generated_at\":\"2026-11-26T00:00:00Z\",\"entries\":[{"
		   "\"id\":\"s1\",\"cves\":[\"CVE-2026-1111\"],\"package\":\"pkg\","
		   "\"version\":\"1.0.0\",\"reference\":\"oci://r.io/a/b:1.0.0\","
		   "\"manifest_digest\":\"" DIGEST_A "\","
		   "\"role\":\"mitigation\","
		   "\"selector\":{\"labels\":{\"env\":[\"prod\x7f\"]}}}]}");
}

static int make_self_signed_window(const char *alg, __s32 not_before_adj,
				   __s32 not_after_adj, EVP_PKEY **out_key,
				   X509 **out_x509, __u8 **out_der,
				   size_t *out_der_len)
{
	X509V3_CTX v3ctx;
	X509_EXTENSION *ext;
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *pkey = NULL;
	X509_NAME *name;
	X509 *x509 = NULL;
	__u8 *der = NULL;
	int der_len;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
	if (!pctx)
		return -ENOTSUP;
	if (EVP_PKEY_keygen_init(pctx) <= 0 ||
	    (!strcmp(alg, "RSA") &&
	     EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) ||
	    EVP_PKEY_generate(pctx, &pkey) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return -EIO;
	}
	EVP_PKEY_CTX_free(pctx);

	x509 = X509_new();
	ASSERT_TRUE(x509);
	X509_set_version(x509, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_getm_notBefore(x509), not_before_adj);
	X509_gmtime_adj(X509_getm_notAfter(x509), not_after_adj);
	X509_set_pubkey(x509, pkey);
	name = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const __u8 *)"feed-test", -1, -1, 0);
	X509_set_issuer_name(x509, name);
	X509V3_set_ctx_nodb(&v3ctx);
	X509V3_set_ctx(&v3ctx, x509, x509, NULL, NULL, 0);
	ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier,
				  "hash");
	ASSERT_TRUE(ext);
	X509_add_ext(x509, ext, -1);
	X509_EXTENSION_free(ext);
	ASSERT_TRUE(X509_sign(x509, pkey, !strcmp(alg, "ML-DSA-87") ?
			      NULL : EVP_sha256()) > 0);

	der_len = i2d_X509(x509, &der);
	ASSERT_TRUE(der_len > 0);
	{
		__u8 *buf = xmalloc((size_t)der_len);

		if (!buf) {
			OPENSSL_free(der);
			X509_free(x509);
			EVP_PKEY_free(pkey);
			return -ENOMEM;
		}
		memcpy(buf, der, (size_t)der_len);
		*out_der = buf;
	}
	OPENSSL_free(der);
	*out_der_len = (size_t)der_len;
	*out_key = pkey;
	*out_x509 = x509;
	return 0;
}

static int make_self_signed(const char *alg, EVP_PKEY **out_key, X509 **out_x509,
			    __u8 **out_der, size_t *out_der_len)
{
	return make_self_signed_window(alg, 0, 86400, out_key, out_x509,
				       out_der, out_der_len);
}

static void sign_cms(EVP_PKEY *pkey, X509 *x509, const EVP_MD *md,
		     const __u8 *payload, size_t payload_len,
		     __u8 **out_sig, size_t *out_sig_len)
{
	__u32 flags = CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP |
		      CMS_NO_SIGNING_TIME | CMS_USE_KEYID;
	CMS_ContentInfo *cms;
	BIO *in, *out;
	char *mem = NULL;
	__u8 *buf;
	long len;

	in = BIO_new_mem_buf(payload, (int)payload_len);
	ASSERT_TRUE(in);
	cms = CMS_sign(NULL, NULL, NULL, NULL,
		       CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED |
		       CMS_STREAM);
	ASSERT_TRUE(cms);
	ASSERT_TRUE(CMS_add1_signer(cms, x509, pkey, md, flags));
	ASSERT_EQ(CMS_final(cms, in, NULL, CMS_NOCERTS | CMS_BINARY), 1);
	out = BIO_new(BIO_s_mem());
	ASSERT_TRUE(out);
	ASSERT_TRUE(i2d_CMS_bio_stream(out, cms, NULL, 0) > 0);
	len = BIO_get_mem_data(out, &mem);
	ASSERT_TRUE(len > 0);
	buf = xmalloc((size_t)len);
	if (!buf)
		abort();
	memcpy(buf, mem, (size_t)len);
	*out_sig = buf;
	*out_sig_len = (size_t)len;
	BIO_free(out);
	CMS_ContentInfo_free(cms);
	BIO_free(in);
}

static void test_verify_cms_and_files(void)
{
	static const char doc[] =
		"{\"schema\":1,\"feed_id\":\"verified-feed\","
		"\"generated_at\":\"2026-11-26T01:02:03Z\","
		"\"entries\":[{\"id\":\"cve-2026-31431-af-alg-block\","
		"\"cves\":[\"CVE-2026-31431\"],"
		"\"package\":\"cve-2026-31431-af-alg-block\","
		"\"version\":\"1.0.0\","
		"\"reference\":\"oci://quay.io/shirudo/af-alg:1.0.0\","
		"\"manifest_digest\":\"" DIGEST_A "\","
		"\"role\":\"mitigation\",\"selector\":{},\"description\":\"ok\"}]}\n";
	__u8 *der = NULL, *sig = NULL, *rsa_der = NULL, *rsa_sig = NULL;
	size_t der_len = 0, sig_len = 0, rsa_der_len = 0, rsa_sig_len = 0;
	char dir[] = "/tmp/unit-bpm-feed-XXXXXX";
	char feed_path[128], sig_path[128], cert_path[128];
	EVP_PKEY *pkey = NULL, *other_key = NULL, *rsa_key = NULL;
	X509 *x509 = NULL, *other_x509 = NULL, *rsa_x509 = NULL;
	__u8 *other_der = NULL;
	size_t other_der_len = 0;
	struct cert cert = {}, other_cert = {}, rsa_cert = {};
	struct bpm_feed feed = {};
	int fd;

	if (make_self_signed("ML-DSA-87", &pkey, &x509, &der, &der_len) == -ENOTSUP)
		unit_skip("OpenSSL without ML-DSA-87");
	sign_cms(pkey, x509, EVP_sha512(), (const __u8 *)doc, sizeof(doc) - 1,
		 &sig, &sig_len);
	ASSERT_EQ(cert_read_der(der, der_len, &cert), 0);

	/* Valid ML-DSA-87 detached CMS signature verifies and parses. */
	ASSERT_EQ(bpm_feed_verify_memory((const __u8 *)doc, sizeof(doc) - 1,
					 sig, sig_len, &cert, &feed), 0);
	EXPECT_STREQ(feed.feed_id, "verified-feed");
	EXPECT_EQ(feed.n_entries, 1);
	bpm_feed_free(&feed);

	/* Tampered payload fails with -EKEYREJECTED. */
	{
		char tampered[sizeof(doc)];

		memcpy(tampered, doc, sizeof(doc));
		tampered[20] ^= 1;
		EXPECT_EQ(bpm_feed_verify_memory((const __u8 *)tampered,
						 sizeof(doc) - 1, sig, sig_len,
						 &cert, &feed), -EKEYREJECTED);
	}

	/* Wrong ML-DSA-87 certificate fails with -EKEYREJECTED. */
	ASSERT_EQ(make_self_signed("ML-DSA-87", &other_key, &other_x509,
				   &other_der, &other_der_len), 0);
	ASSERT_EQ(cert_read_der(other_der, other_der_len, &other_cert), 0);
	EXPECT_EQ(bpm_feed_verify_memory((const __u8 *)doc, sizeof(doc) - 1,
					 sig, sig_len, &other_cert, &feed),
		  -EKEYREJECTED);

	/* Classical RSA-2048 certificate is refused even with a valid CMS sig. */
	ASSERT_EQ(make_self_signed("RSA", &rsa_key, &rsa_x509, &rsa_der,
				   &rsa_der_len), 0);
	sign_cms(rsa_key, rsa_x509, EVP_sha256(), (const __u8 *)doc,
		 sizeof(doc) - 1, &rsa_sig, &rsa_sig_len);
	ASSERT_EQ(cert_read_der(rsa_der, rsa_der_len, &rsa_cert), 0);
	EXPECT_EQ(bpm_feed_verify_memory((const __u8 *)doc, sizeof(doc) - 1,
					 rsa_sig, rsa_sig_len, &rsa_cert,
					 &feed), -EKEYREJECTED);

	/* Expired ML-DSA-87 certificate is refused even with a valid CMS sig. */
	{
		size_t exp_der_len = 0, exp_sig_len = 0;
		__u8 *exp_der = NULL, *exp_sig = NULL;
		EVP_PKEY *exp_key = NULL;
		struct cert exp_cert = {};
		X509 *exp_x509 = NULL;

		ASSERT_EQ(make_self_signed_window("ML-DSA-87", -172800, -86400,
						  &exp_key, &exp_x509, &exp_der,
						  &exp_der_len), 0);
		sign_cms(exp_key, exp_x509, EVP_sha512(), (const __u8 *)doc,
			 sizeof(doc) - 1, &exp_sig, &exp_sig_len);
		ASSERT_EQ(cert_read_der(exp_der, exp_der_len, &exp_cert), 0);
		EXPECT_EQ(bpm_feed_verify_memory((const __u8 *)doc,
						 sizeof(doc) - 1, exp_sig,
						 exp_sig_len, &exp_cert, &feed),
			  -EKEYREJECTED);
		cert_free(&exp_cert);
		xfree(exp_sig, exp_sig_len);
		xfree(exp_der, exp_der_len);
		X509_free(exp_x509);
		EVP_PKEY_free(exp_key);
	}

	/* File-based verification round-trip. */
	ASSERT_TRUE(mkdtemp(dir));
	ASSERT_TRUE(strsprintf(feed_path, sizeof(feed_path), "%s/feed.json",
			       dir) > 0);
	ASSERT_TRUE(strsprintf(sig_path, sizeof(sig_path), "%s/feed.sig",
			       dir) > 0);
	ASSERT_TRUE(strsprintf(cert_path, sizeof(cert_path), "%s/cert.der",
			       dir) > 0);

	fd = open(feed_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, doc, sizeof(doc) - 1), 0);
	close(fd);
	fd = open(sig_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, sig, sig_len), 0);
	close(fd);
	fd = open(cert_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, der, der_len), 0);
	close(fd);

	ASSERT_EQ(bpm_feed_verify_files(feed_path, sig_path, cert_path, &feed), 0);
	EXPECT_EQ(feed.n_entries, 1);
	bpm_feed_free(&feed);

	unlink(feed_path);
	unlink(sig_path);
	unlink(cert_path);
	rmdir(dir);

	cert_free(&rsa_cert);
	cert_free(&other_cert);
	cert_free(&cert);
	xfree(rsa_sig, rsa_sig_len);
	xfree(rsa_der, rsa_der_len);
	xfree(other_der, other_der_len);
	xfree(sig, sig_len);
	xfree(der, der_len);
	X509_free(rsa_x509);
	X509_free(other_x509);
	X509_free(x509);
	EVP_PKEY_free(rsa_key);
	EVP_PKEY_free(other_key);
	EVP_PKEY_free(pkey);
}

static const struct unit_case cases[] = {
	UNIT_CASE(test_cve_ok),
	UNIT_CASE(test_parse_and_emit_roundtrip),
	UNIT_CASE(test_reject_invalid),
	UNIT_CASE(test_verify_cms_and_files),
	{},
};

UNIT_SUITE(bpm_feed, cases);
