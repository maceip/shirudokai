// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Unit tests for OTLP origin digests, signed headers and classification.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zlib.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <shirudo/byteorder.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "json.h"
#include "malloc.h"
#include "tools/quote-check/row.h"
#include "upatch_maps_otel.h"
#include "unit.h"

#define TEST_AK_ATTRS		0x00050072u
#define TEST_CLOCK		0x0102030405060708ull
#define TEST_RESET_COUNT	7u

static EVP_PKEY *test_ak_key(void)
{
	static EVP_PKEY *key;

	if (!key)
		key = EVP_EC_gen("P-256");
	ASSERT_TRUE(key);
	return key;
}

static int software_quote_cb(const __u8 digest[32], struct tpm_key *ak,
			     struct tpm_attestation *att, void *ctx)
{
	static const __u8 pcr_digest[TPM_DIGEST_LEN] = { 0xe3, 0xb0, 0xc4 };
	__u8 qualified[TPM_NAME_LEN], att_hash[CRYPTO_SHA256_LEN];
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(test_ak_key(), NULL);
	__u8 der[128], r[32], s[32], *p;
	struct tpm_public pub = {};
	BIGNUM *bx = NULL, *by = NULL;
	size_t der_len = sizeof(der);
	const __u8 *dp;
	ECDSA_SIG *sig;

	if (!pctx)
		return -ENOMEM;
	pub.type = TPM_ALG_ECC;
	pub.attrs = TEST_AK_ATTRS;
	pub.sym_alg = TPM_ALG_NULL;
	pub.scheme = TPM_ALG_ECDSA;
	pub.scheme_hash = TPM_ALG_SHA256;
	pub.curve = TPM_ECC_NIST_P256;
	ASSERT_EQ(EVP_PKEY_get_bn_param(test_ak_key(), OSSL_PKEY_PARAM_EC_PUB_X,
					&bx), 1);
	ASSERT_EQ(EVP_PKEY_get_bn_param(test_ak_key(), OSSL_PKEY_PARAM_EC_PUB_Y,
					&by), 1);
	ASSERT_EQ(BN_bn2binpad(bx, pub.x, 32), 32);
	ASSERT_EQ(BN_bn2binpad(by, pub.y, 32), 32);
	BN_free(bx);
	BN_free(by);

	ASSERT_EQ(tpm_public_marshal(&pub, ak->public, sizeof(ak->public),
				     &ak->public_len), 0);
	ASSERT_EQ(tpm_object_name(ak->public, ak->public_len, ak->name), 0);
	ak->name_len = TPM_NAME_LEN;
	ASSERT_EQ(tpm_qualified_name(TPM_RH_ENDORSEMENT, ak->name, qualified),
		  0);

	p = att->attest;
	put_be32(p, TPM_GENERATED);
	p += 4;
	put_be16(p, TPM_ST_ATTEST_QUOTE);
	p += 2;
	p += tpm_put2b(p, qualified, TPM_NAME_LEN);
	p += tpm_put2b(p, digest, 32);
	put_be32(p, (__u32)(TEST_CLOCK >> 32));
	put_be32(p + 4, (__u32)TEST_CLOCK);
	p += 8;
	put_be32(p, TEST_RESET_COUNT);
	put_be32(p + 4, 1);
	p += 8;
	*p++ = 1;
	put_be32(p, 0);
	put_be32(p + 4, 1);
	p += 8;
	put_be32(p, 1);
	put_be16(p + 4, TPM_ALG_SHA256);
	p += 6;
	*p++ = TPM_PCR_SELECT_LEN;
	*p++ = 0;
	*p++ = 0;
	*p++ = 0;
	p += tpm_put2b(p, pcr_digest, sizeof(pcr_digest));
	att->attest_len = (size_t)(p - att->attest);

	ASSERT_EQ(sha256_buffer(att->attest, att->attest_len, att_hash), 0);
	ASSERT_TRUE(EVP_PKEY_sign_init(pctx) == 1);
	ASSERT_TRUE(EVP_PKEY_sign(pctx, der, &der_len, att_hash,
				  sizeof(att_hash)) == 1);
	dp = der;
	sig = d2i_ECDSA_SIG(NULL, &dp, (long)der_len);
	ASSERT_TRUE(sig);
	ASSERT_EQ(BN_bn2binpad(ECDSA_SIG_get0_r(sig), r, 32), 32);
	ASSERT_EQ(BN_bn2binpad(ECDSA_SIG_get0_s(sig), s, 32), 32);
	ECDSA_SIG_free(sig);
	EVP_PKEY_CTX_free(pctx);

	p = att->signature;
	put_be16(p, TPM_ALG_ECDSA);
	put_be16(p + 2, TPM_ALG_SHA256);
	p += 4;
	p += tpm_put2b(p, r, 32);
	p += tpm_put2b(p, s, 32);
	att->signature_len = (size_t)(p - att->signature);
	if (ctx)
		*(struct tpm_key *)ctx = *ak;
	return 0;
}

static void origin_digest_binds_domain_boot_seq_and_body(void)
{
	__u8 body1[32] = { 1 }, body2[32] = { 2 };
	__u8 d1[32], d2[32], manual[32], seq_be[8];
	struct sha256_ctx ctx;

	ASSERT_EQ(otel_origin_digest("boot-a", 1, body1, d1), 0);

	/* Matches exact domain-separated layout "shirudo-otel-origin-v1\0". */
	put_be32(seq_be, 0);
	put_be32(seq_be + 4, 1);
	ASSERT_EQ(sha256_init(&ctx), 0);
	ASSERT_EQ(sha256_update(&ctx, "shirudo-otel-origin-v1", 23), 0);
	ASSERT_EQ(sha256_update(&ctx, seq_be, 8), 0);
	ASSERT_EQ(sha256_update(&ctx, body1, 32), 0);
	ASSERT_EQ(sha256_update(&ctx, "boot-a", 6), 0);
	ASSERT_EQ(sha256_final(&ctx, manual), 0);
	sha256_free(&ctx);
	EXPECT_MEMEQ(d1, manual, 32);

	/* Changing boot_id, seq or body changes the digest. */
	ASSERT_EQ(otel_origin_digest("boot-b", 1, body1, d2), 0);
	EXPECT_TRUE(memcmp(d1, d2, 32) != 0);
	ASSERT_EQ(otel_origin_digest("boot-a", 2, body1, d2), 0);
	EXPECT_TRUE(memcmp(d1, d2, 32) != 0);
	ASSERT_EQ(otel_origin_digest("boot-a", 1, body2, d2), 0);
	EXPECT_TRUE(memcmp(d1, d2, 32) != 0);

	/* Rejects invalid inputs. */
	EXPECT_EQ(otel_origin_digest(NULL, 1, body1, d2), -EINVAL);
	EXPECT_EQ(otel_origin_digest("", 1, body1, d2), -EINVAL);
	EXPECT_EQ(otel_origin_digest("boot with space", 1, body1, d2), -EINVAL);
	EXPECT_EQ(otel_origin_digest("boot\ttab", 1, body1, d2), -EINVAL);
	EXPECT_EQ(otel_origin_digest("boot-a", 1, NULL, d2), -EINVAL);
	EXPECT_EQ(otel_origin_digest("boot-a", 1, body1, NULL), -EINVAL);
}

static void signed_headers_roundtrip_through_quote_check(void)
{
	static const char payload[] =
		"{\"resourceMetrics\":[{\"scopeMetrics\":[]}]}";
	struct tpm_key ak = {};
	struct otel_opts opts = {
		.tpm_sign = true,
		.boot_id = "boot-9944-uuid",
		.export_seq = 19,
		.quote_fn = software_quote_cb,
		.quote_ctx = &ak,
	};
	struct otel_signed_headers hdrs;
	__u8 body_sha256[32];
	struct quote_otel_envelope env = {};
	struct quote_result res;

	ASSERT_EQ(otel_sign_headers(&opts, payload, strlen(payload), &hdrs), 0);
	EXPECT_STREQ(hdrs.boot_id, "boot-9944-uuid");
	EXPECT_STREQ(hdrs.export_seq, "19");
	EXPECT_UEQ(hdrs.seq, 19);
	EXPECT_UEQ(strlen(hdrs.ak_name), 2 * TPM_NAME_LEN);

	ASSERT_EQ(sha256_buffer(payload, strlen(payload), body_sha256), 0);
	env.ak_name_hex = hdrs.ak_name;
	env.attest_hex = hdrs.attest;
	env.sig_hex = hdrs.signature;
	env.ak_public = ak.public;
	env.ak_public_len = ak.public_len;
	env.boot_id = hdrs.boot_id;
	env.export_seq = hdrs.export_seq;
	env.body_sha256 = body_sha256;

	ASSERT_EQ(quote_otel_check(&env, &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_OK);
	EXPECT_UEQ(res.reset_count, TEST_RESET_COUNT);
	EXPECT_UEQ(res.clock, TEST_CLOCK);
	EXPECT_UEQ(res.seq, 19);

	/* Tampering with body digest fails verification. */
	body_sha256[0] ^= 0xff;
	ASSERT_EQ(quote_otel_check(&env, &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_BODY_MISMATCH);
}

static void reserved_shirudo_headers_are_refused(void)
{
	struct map_view v = {
		.type = BPF_MAP_TYPE_ARRAY,
		.type_name = "array",
	};
	struct otel_opts opts = {
		.endpoint = "http://127.0.0.1:1",
		.retries = 0,
	};

	strscpy_literal(v.upatch, "test");
	strscpy_literal(v.name, "m");
	ASSERT_EQ(setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS",
			 "X-Shirudo-TPM-Signature=deadbeef", 1), 0);
	EXPECT_EQ(upatch_maps_otel_send(&v, OTEL_FORCE_LOG, &opts), -EINVAL);
	ASSERT_EQ(setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS",
			 "X-Shirudo-Boot-ID=spoofed", 1), 0);
	EXPECT_EQ(upatch_maps_otel_send(&v, OTEL_FORCE_LOG, &opts), -EINVAL);
	unsetenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS");
}

struct shield_pair {
	__u64	hits;
	__u64	activity;
};

static void shield_metrics_export_and_origin_signature(void)
{
	struct shield_pair per_cpu[2] = {
		{ .hits = 3, .activity = 50 },
		{ .hits = 9, .activity = 70 },
	};
	__u32 k0 = 0;
	struct map_entry entry = {
		.key	= &k0,
		.value	= per_cpu,
	};
	struct map_view v = {};
	enum otel_signal signal = OTEL_LOG;
	char reason[128] = {};
	char *payload = NULL;
	size_t payload_len = 0;
	struct tpm_key ak = {};
	struct otel_opts opts = {
		.tpm_sign	= true,
		.boot_id	= "boot-shield-01",
		.export_seq	= 4,
		.quote_fn	= software_quote_cb,
		.quote_ctx	= &ak,
	};
	struct otel_signed_headers hdrs = {};
	struct quote_otel_envelope env = {};
	struct quote_result res = {};
	__u8 body_sha256[32];
	int u64_id, st_id;
	struct btf *btf;

	btf = btf__new_empty();
	ASSERT_TRUE(btf);
	u64_id = btf__add_int(btf, "__u64", 8, 0);
	st_id = btf__add_struct(btf, "shield_pair", sizeof(per_cpu[0]));
	ASSERT_TRUE(u64_id > 0 && st_id > 0);
	ASSERT_EQ(btf__add_field(btf, "hits", u64_id, 0, 0), 0);
	ASSERT_EQ(btf__add_field(btf, "activity", u64_id, 64, 0), 0);

	strscpy_literal(v.upatch, "cve-2026-31431");
	strscpy_literal(v.name, "shield_stats");
	strscpy_literal(v.location, "kprobe/target_fn");
	v.type = BPF_MAP_TYPE_PERCPU_ARRAY;
	v.type_name = "percpu_array";
	v.key_size = sizeof(__u32);
	v.value_size = sizeof(per_cpu[0]);
	v.value_stride = sizeof(per_cpu[0]);
	v.max_entries = 1;
	v.n_entries = 1;
	v.n_cpus = 2;
	v.lifetime_start_ns = 1700000000123456789ULL;
	v.has_payload = true;
	memset(v.payload, 0xab, sizeof(v.payload));
	v.btf = btf;
	v.value_type_id = (__u32)st_id;
	v.entries = &entry;

	ASSERT_EQ(upatch_maps_otel_classify(&v, &signal, reason,
					    sizeof(reason)), 0);
	EXPECT_EQ(signal, OTEL_METRIC);
	EXPECT_STREQ(reason, "trusted shield counter map");

	ASSERT_EQ(upatch_maps_otel_build_shield_metrics(&v, &payload,
							&payload_len), 0);
	ASSERT_TRUE(payload && payload_len > 0);
	EXPECT_TRUE(str_contains(payload, "\"name\":\"shirudo.shield.hits\""));
	EXPECT_TRUE(str_contains(payload, "\"asInt\":\"12\""));
	EXPECT_TRUE(str_contains(payload, "\"name\":\"shirudo.shield.activity\""));
	EXPECT_TRUE(str_contains(payload, "\"asInt\":\"120\""));
	EXPECT_TRUE(str_contains(payload, "\"aggregationTemporality\":2"));
	EXPECT_TRUE(str_contains(payload, "\"isMonotonic\":true"));
	EXPECT_TRUE(str_contains(payload,
				 "\"startTimeUnixNano\":\"1700000000123456789\""));
	EXPECT_TRUE(str_contains(payload, "\"shirudo.upatch.payload_sha256\""));

	/* TPM origin signature covers the exact shield metric OTLP body. */
	ASSERT_EQ(otel_sign_headers(&opts, payload, payload_len, &hdrs), 0);
	ASSERT_EQ(sha256_buffer(payload, payload_len, body_sha256), 0);
	env.ak_name_hex = hdrs.ak_name;
	env.attest_hex = hdrs.attest;
	env.sig_hex = hdrs.signature;
	env.ak_public = ak.public;
	env.ak_public_len = ak.public_len;
	env.boot_id = hdrs.boot_id;
	env.export_seq = hdrs.export_seq;
	env.body_sha256 = body_sha256;
	ASSERT_EQ(quote_otel_check(&env, &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_OK);

	xfree(payload, JSON_MAX_BYTES);
	btf__free(btf);
}

struct captured_post {
	char	ak_name[2 * TPM_NAME_LEN + 1];
	char	attest[2 * TPM_ATTEST_MAX + 1];
	char	signature[2 * TPM_SIGNATURE_MAX + 1];
	char	boot_id[OTEL_BOOT_ID_MAX + 1];
	char	export_seq[32];
	bool	has_gzip_encoding;
	size_t	body_len;
	__u8	body[4096];
};

static int copy_trimmed_header(char *dst, size_t cap, const char *s, size_t len)
{
	while (len && (*s == ' ' || *s == '\t')) {
		s++;
		len--;
	}
	while (len && (s[len - 1] == ' ' || s[len - 1] == '\t'))
		len--;
	return span_to_str(dst, cap, s, len);
}

static int match_header_value(const char *tok, size_t tok_len,
			      const char *prefix, char *dst, size_t cap)
{
	size_t plen = strlen(prefix), i;

	if (tok_len < plen)
		return 0;
	for (i = 0; i < plen; i++) {
		if (tolower((__u8)tok[i]) != tolower((__u8)prefix[i]))
			return 0;
	}
	if (copy_trimmed_header(dst, cap, tok + plen, tok_len - plen))
		return -1;
	return 1;
}

static int serve_one_otel_post(int listen_fd, int pipe_wr)
{
	static const char resp[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 2\r\n"
		"Connection: close\r\n\r\n{}";
	struct captured_post cap = {};
	const char *hdr_end = NULL, *tok;
	__u64 content_len = 0;
	size_t got = 0, hdr_len = 0, tok_len, sent = 0;
	bool have_len = false;
	char req[16384];
	int conn;

	conn = accept(listen_fd, NULL, NULL);
	if (conn < 0)
		return 1;
	while (got < sizeof(req)) {
		ssize_t n = read(conn, req + got, sizeof(req) - got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		got += (size_t)n;
		if (!hdr_end) {
			hdr_end = span_find(req, got, "\r\n\r\n");
			if (hdr_end) {
				hdr_len = (size_t)(hdr_end - req);
				for_each_token(tok, tok_len, req, hdr_len,
					       "\r\n") {
					char num[32];
					int m;

					m = match_header_value(tok, tok_len,
							       "Content-Length:",
							       num,
							       sizeof(num));
					if (!m)
						continue;
					if (m < 0 ||
					    parse_u64(num, strlen(num),
						      sizeof(cap.body),
						      &content_len)) {
						close(conn);
						return 1;
					}
					have_len = true;
				}
				if (!have_len) {
					close(conn);
					return 1;
				}
			}
		}
		if (hdr_end && got >= hdr_len + 4 + (size_t)content_len)
			break;
	}
	if (!hdr_end || got < hdr_len + 4 + (size_t)content_len) {
		close(conn);
		return 1;
	}
	for_each_token(tok, tok_len, req, hdr_len, "\r\n") {
		char enc[32];
		int m;

		m = match_header_value(tok, tok_len, "Content-Encoding:",
				       enc, sizeof(enc));
		if (m < 0)
			goto bad;
		if (m > 0) {
			if (str_equals_nocase(enc, "gzip"))
				cap.has_gzip_encoding = true;
			continue;
		}
		if (match_header_value(tok, tok_len, "X-Shirudo-TPM-AK-Name:",
				       cap.ak_name, sizeof(cap.ak_name)) < 0 ||
		    match_header_value(tok, tok_len, "X-Shirudo-TPM-Attest:",
				       cap.attest, sizeof(cap.attest)) < 0 ||
		    match_header_value(tok, tok_len, "X-Shirudo-TPM-Signature:",
				       cap.signature,
				       sizeof(cap.signature)) < 0 ||
		    match_header_value(tok, tok_len, "X-Shirudo-Boot-ID:",
				       cap.boot_id, sizeof(cap.boot_id)) < 0 ||
		    match_header_value(tok, tok_len, "X-Shirudo-Export-Seq:",
				       cap.export_seq,
				       sizeof(cap.export_seq)) < 0)
			goto bad;
	}
	cap.body_len = (size_t)content_len;
	memcpy(cap.body, req + hdr_len + 4, cap.body_len);
	if (write(conn, resp, sizeof(resp) - 1) != (ssize_t)(sizeof(resp) - 1))
		goto bad;
	close(conn);
	while (sent < sizeof(cap)) {
		ssize_t n = write(pipe_wr, (const __u8 *)&cap + sent,
				  sizeof(cap) - sent);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return 1;
		sent += (size_t)n;
	}
	return 0;
bad:
	close(conn);
	return 1;
}

static void gzip_signed_post_roundtrips_through_quote_check(void)
{
	static const char status_body[] = "{\"status\":\"ok\"}";
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_addr	= { .s_addr = htonl(INADDR_LOOPBACK) },
	};
	socklen_t addr_len = sizeof(addr);
	struct quote_otel_envelope env = {};
	struct captured_post cap = {};
	struct quote_result res = {};
	struct tpm_key ak = {};
	struct otel_opts opts = {
		.retries	= 0,
		.tpm_sign	= true,
		.boot_id	= "boot-gzip-77",
		.export_seq	= 23,
		.quote_fn	= software_quote_cb,
		.quote_ctx	= &ak,
	};
	__u8 body_sha256[32], plain_sha256[32];
	int listen_fd, pfd[2], status = 0, send_rc;
	char plain[8192];
	char endpoint[64];
	z_stream zs = {};
	size_t got = 0;
	pid_t pid;

	test_ak_key();
	listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ASSERT_TRUE(listen_fd >= 0);
	ASSERT_EQ(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
	ASSERT_EQ(getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len),
		  0);
	ASSERT_EQ(listen(listen_fd, 1), 0);
	ASSERT_TRUE(strsprintf(endpoint, sizeof(endpoint),
			       "http://127.0.0.1:%u",
			       (__u32)ntohs(addr.sin_port)) > 0);
	opts.endpoint = endpoint;
	ASSERT_EQ(pipe2(pfd, O_CLOEXEC), 0);

	pid = fork();
	ASSERT_TRUE(pid >= 0);
	if (pid == 0) {
		int rc;

		close(pfd[0]);
		rc = serve_one_otel_post(listen_fd, pfd[1]);
		close(pfd[1]);
		close(listen_fd);
		_exit(rc);
	}
	close(pfd[1]);
	close(listen_fd);

	ASSERT_EQ(setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip", 1), 0);
	send_rc = otel_send_log_string(&opts, "shirudo.status",
				       "shirudo.status.report", 9, "INFO",
				       status_body, sizeof(status_body) - 1,
				       "shirudo.status", "ok");
	unsetenv("OTEL_EXPORTER_OTLP_COMPRESSION");
	ASSERT_EQ(send_rc, 0);

	while (got < sizeof(cap)) {
		ssize_t n = read(pfd[0], (__u8 *)&cap + got, sizeof(cap) - got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	close(pfd[0]);
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ASSERT_UEQ(got, sizeof(cap));

	EXPECT_TRUE(cap.has_gzip_encoding);
	ASSERT_TRUE(cap.body_len > 10);
	EXPECT_UEQ(cap.body[0], 0x1f);
	EXPECT_UEQ(cap.body[1], 0x8b);

	/* Wire body inflates cleanly to the OTLP JSON payload. */
	zs.next_in = cap.body;
	zs.avail_in = (uInt)cap.body_len;
	zs.next_out = (__u8 *)plain;
	zs.avail_out = sizeof(plain) - 1;
	ASSERT_EQ(inflateInit2(&zs, 15 + 16), Z_OK);
	ASSERT_EQ(inflate(&zs, Z_FINISH), Z_STREAM_END);
	plain[zs.total_out] = '\0';
	ASSERT_EQ(inflateEnd(&zs), Z_OK);
	EXPECT_TRUE(str_contains(plain, "\"resourceLogs\""));

	/* Quote verifies against the compressed HTTP wire bytes. */
	ASSERT_EQ(sha256_buffer(cap.body, cap.body_len, body_sha256), 0);
	env.ak_name_hex = cap.ak_name;
	env.attest_hex = cap.attest;
	env.sig_hex = cap.signature;
	env.ak_public = ak.public;
	env.ak_public_len = ak.public_len;
	env.boot_id = cap.boot_id;
	env.export_seq = cap.export_seq;
	env.body_sha256 = body_sha256;
	ASSERT_EQ(quote_otel_check(&env, &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_OK);
	EXPECT_UEQ(res.seq, 23);

	/* Hashing the uncompressed JSON fails with QUOTE_BODY_MISMATCH. */
	ASSERT_EQ(sha256_buffer(plain, zs.total_out, plain_sha256), 0);
	env.body_sha256 = plain_sha256;
	ASSERT_EQ(quote_otel_check(&env, &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_BODY_MISMATCH);
}

static const struct unit_case cases[] = {
	UNIT_CASE(origin_digest_binds_domain_boot_seq_and_body),
	UNIT_CASE(signed_headers_roundtrip_through_quote_check),
	UNIT_CASE(reserved_shirudo_headers_are_refused),
	UNIT_CASE(shield_metrics_export_and_origin_signature),
	UNIT_CASE(gzip_signed_post_roundtrips_through_quote_check),
	{}
};

UNIT_SUITE(upatch_maps_otel, cases);
