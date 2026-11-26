// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Unit tests for OTLP origin digests, signed headers and classification.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

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

static const struct unit_case cases[] = {
	UNIT_CASE(origin_digest_binds_domain_boot_seq_and_body),
	UNIT_CASE(signed_headers_roundtrip_through_quote_check),
	UNIT_CASE(reserved_shirudo_headers_are_refused),
	UNIT_CASE(shield_metrics_export_and_origin_signature),
	{}
};

UNIT_SUITE(upatch_maps_otel, cases);
