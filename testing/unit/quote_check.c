// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The rows of shirudo-quote-check, on quotes a software P-256 key signs
 * in place of a TPM's attestation key.
 */

#include <stdbool.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <shirudo/byteorder.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "tools/quote-check/row.h"
#include "unit.h"

#define TPM_ECC_NIST_P384	0x0004u
#define TPM_AK_ATTRS		0x00050072u
#define TPM_SIGNATURE_LEN	(2 + 2 + 2 + 32 + 2 + 32)

#define ATTEST_MAGIC_OFF	0
#define ATTEST_CLOCK_OFF	(4 + 2 + 2 + TPM_NAME_LEN + 2 + TPM_DIGEST_LEN)
#define SIG_ALG_OFF		0
#define SIG_R_OFF		(2 + 2 + 2)
#define SIG_S_OFF		(SIG_R_OFF + 32 + 2)

#define QUOTE_CLOCK		0xfedcba9876543210ull
#define QUOTE_RESET_COUNT	0x89abcdefu
#define QUOTE_RESTART_COUNT	3
#define QUOTE_FIRMWARE		0x2026111100000001ull

static const char keepalive_body[] = "{\"schema\":\"shirudo.keepalive/1\"}";

/* What a test sets before quote_sign() makes the bytes of a row from it. */
struct quote {
	struct tpm_public	ak;
	bool			signer_is_plain_name;
	__u8			extra[64];
	size_t			extra_len;
	__u32			pcr_mask;
	bool			certifies_nv;

	__u8			ak_public[TPM_PUBLIC_MAX];
	size_t			ak_public_len;
	__u8			ak_name[TPM_NAME_LEN];
	__u8			attest[TPM_ATTEST_MAX];
	size_t			attest_len;
	__u8			sig[TPM_SIGNATURE_LEN];
	char			body_sha256[QUOTE_BODY_HEX_LEN + 1];
};

static EVP_PKEY *software_ak(void)
{
	static EVP_PKEY *key;

	if (!key)
		key = EVP_EC_gen("P-256");
	ASSERT_TRUE(key);
	return key;
}

static void software_ak_point(__u8 x[32], __u8 y[32])
{
	BIGNUM *bx = NULL, *by = NULL;

	ASSERT_EQ(EVP_PKEY_get_bn_param(software_ak(),
					OSSL_PKEY_PARAM_EC_PUB_X, &bx), 1);
	ASSERT_EQ(EVP_PKEY_get_bn_param(software_ak(),
					OSSL_PKEY_PARAM_EC_PUB_Y, &by), 1);
	ASSERT_EQ(BN_bn2binpad(bx, x, 32), 32);
	ASSERT_EQ(BN_bn2binpad(by, y, 32), 32);
	BN_free(bx);
	BN_free(by);
}

static void software_ak_sign(const __u8 digest[CRYPTO_SHA256_LEN],
			     __u8 r[32], __u8 s[32])
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(software_ak(), NULL);
	size_t der_len = 128;
	const __u8 *p;
	ECDSA_SIG *sig;
	__u8 der[128];

	ASSERT_TRUE(ctx);
	ASSERT_TRUE(EVP_PKEY_sign_init(ctx) == 1);
	ASSERT_TRUE(EVP_PKEY_sign(ctx, der, &der_len, digest,
				  CRYPTO_SHA256_LEN) == 1);
	p = der;
	sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
	ASSERT_TRUE(sig);
	ASSERT_EQ(BN_bn2binpad(ECDSA_SIG_get0_r(sig), r, 32), 32);
	ASSERT_EQ(BN_bn2binpad(ECDSA_SIG_get0_s(sig), s, 32), 32);
	ECDSA_SIG_free(sig);
	EVP_PKEY_CTX_free(ctx);
}

/* A quote of no PCR over the body's SHA-256, by an endorsement primary. */
static void quote_init(struct quote *q)
{
	memset(q, 0, sizeof(*q));
	q->ak.type = TPM_ALG_ECC;
	q->ak.attrs = TPM_AK_ATTRS;
	q->ak.sym_alg = TPM_ALG_NULL;
	q->ak.scheme = TPM_ALG_ECDSA;
	q->ak.scheme_hash = TPM_ALG_SHA256;
	q->ak.curve = TPM_ECC_NIST_P256;
	software_ak_point(q->ak.x, q->ak.y);
	q->extra_len = CRYPTO_SHA256_LEN;
	ASSERT_EQ(sha256_buffer(keepalive_body, strlen(keepalive_body),
				q->extra), 0);
	hex_encode(q->extra, CRYPTO_SHA256_LEN, q->body_sha256);
}

static size_t put_be64_at(__u8 *p, __u64 v)
{
	put_be32(p, (__u32)(v >> 32));
	put_be32(p + 4, (__u32)v);
	return 8;
}

static void quote_marshal_attest(struct quote *q, const __u8 *signer)
{
	static const __u8 digest[TPM_DIGEST_LEN] = { 0xe3, 0xb0, 0xc4 };
	__u8 *p = q->attest;

	put_be32(p, TPM_GENERATED);
	p += 4;
	put_be16(p, q->certifies_nv ? TPM_ST_ATTEST_NV : TPM_ST_ATTEST_QUOTE);
	p += 2;
	p += tpm_put2b(p, signer, TPM_NAME_LEN);
	p += tpm_put2b(p, q->extra, q->extra_len);
	p += put_be64_at(p, QUOTE_CLOCK);
	put_be32(p, QUOTE_RESET_COUNT);
	put_be32(p + 4, QUOTE_RESTART_COUNT);
	p += 8;
	*p++ = 1;
	p += put_be64_at(p, QUOTE_FIRMWARE);
	if (q->certifies_nv) {
		p += tpm_put2b(p, signer, TPM_NAME_LEN);
		put_be16(p, 0);
		p += 2;
		p += tpm_put2b(p, digest, sizeof(digest));
		q->attest_len = (size_t)(p - q->attest);
		return;
	}
	put_be32(p, 1);
	put_be16(p + 4, TPM_ALG_SHA256);
	p += 6;
	*p++ = TPM_PCR_SELECT_LEN;
	*p++ = (__u8)q->pcr_mask;
	*p++ = (__u8)(q->pcr_mask >> 8);
	*p++ = (__u8)(q->pcr_mask >> 16);
	p += tpm_put2b(p, digest, sizeof(digest));
	q->attest_len = (size_t)(p - q->attest);
}

static void quote_sign(struct quote *q)
{
	__u8 digest[CRYPTO_SHA256_LEN], qualified[TPM_NAME_LEN];
	__u8 r[32], s[32], *p = q->sig;

	ASSERT_EQ(tpm_public_marshal(&q->ak, q->ak_public,
				     sizeof(q->ak_public),
				     &q->ak_public_len), 0);
	ASSERT_EQ(tpm_object_name(q->ak_public, q->ak_public_len,
				  q->ak_name), 0);
	ASSERT_EQ(tpm_qualified_name(TPM_RH_ENDORSEMENT, q->ak_name,
				     qualified), 0);
	quote_marshal_attest(q, q->signer_is_plain_name ? q->ak_name :
							  qualified);
	ASSERT_EQ(sha256_buffer(q->attest, q->attest_len, digest), 0);
	software_ak_sign(digest, r, s);
	put_be16(p, TPM_ALG_ECDSA);
	put_be16(p + 2, TPM_ALG_SHA256);
	p += 4;
	p += tpm_put2b(p, r, 32);
	tpm_put2b(p, s, 32);
}

static void quote_row(const struct quote *q, char *row, size_t cap)
{
	char attest[BASE64_LEN(TPM_ATTEST_MAX) + 1];
	char sig[BASE64_LEN(TPM_SIGNATURE_LEN) + 1];
	char ak[BASE64_LEN(TPM_PUBLIC_MAX) + 1];

	ASSERT_EQ(base64_encode(q->attest, q->attest_len, attest,
				sizeof(attest)), 0);
	ASSERT_EQ(base64_encode(q->sig, sizeof(q->sig), sig, sizeof(sig)), 0);
	ASSERT_EQ(base64_encode(q->ak_public, q->ak_public_len, ak,
				sizeof(ak)), 0);
	ASSERT_TRUE(strsprintf(row, cap, "%s\t%s\t%s\t%s", attest, sig, ak,
			       q->body_sha256) > 0);
}

static enum quote_verdict row_verdict(const char *row)
{
	struct quote_result res;

	ASSERT_EQ(quote_row_check(row, strlen(row), &res), 0);
	return res.verdict;
}

static enum quote_verdict quote_verdict(const struct quote *q)
{
	char row[QUOTE_ROW_MAX + 1];

	quote_row(q, row, sizeof(row));
	return row_verdict(row);
}

static void row_line(const char *row, char *line, size_t cap)
{
	struct quote_result res;

	ASSERT_EQ(quote_row_check(row, strlen(row), &res), 0);
	ASSERT_EQ(quote_row_emit(&res, line, cap), 0);
}

static void good_row_is_accepted(void)
{
	char row[QUOTE_ROW_MAX + 1], want[QUOTE_LINE_MAX], line[QUOTE_LINE_MAX];
	char ak_public[BASE64_LEN(TPM_PUBLIC_MAX) + 1];
	__u8 name[TPM_NAME_LEN] = { 0x00, 0x0b };
	char ak_name[2 * TPM_NAME_LEN + 1];
	struct quote_result res;
	struct quote q;

	quote_init(&q);
	quote_sign(&q);
	quote_row(&q, row, sizeof(row));
	ASSERT_EQ(quote_row_check(row, strlen(row), &res), 0);
	ASSERT_EQ(res.verdict, QUOTE_OK);
	ASSERT_EQ(sha256_buffer(q.ak_public, q.ak_public_len, name + 2), 0);
	EXPECT_MEMEQ(res.ak_name, name, sizeof(name));
	ASSERT_UEQ(res.ak_public_len, q.ak_public_len);
	EXPECT_MEMEQ(res.ak_public, q.ak_public, q.ak_public_len);
	EXPECT_UEQ(res.reset_count, QUOTE_RESET_COUNT);
	EXPECT_UEQ(res.restart_count, QUOTE_RESTART_COUNT);
	EXPECT_UEQ(res.clock, QUOTE_CLOCK);

	hex_encode(name, sizeof(name), ak_name);
	ASSERT_EQ(base64_encode(q.ak_public, q.ak_public_len, ak_public,
				sizeof(ak_public)), 0);
	ASSERT_TRUE(strsprintf(want, sizeof(want),
			       "{\"ok\":1,\"ak_name\":\"%s\",\"ak_public\":\"%s\",\"reset_count\":%u,\"restart_count\":%u,\"clock\":%llu}",
			       ak_name, ak_public, QUOTE_RESET_COUNT,
			       QUOTE_RESTART_COUNT, QUOTE_CLOCK) > 0);
	ASSERT_EQ(quote_row_emit(&res, line, sizeof(line)), 0);
	EXPECT_STREQ(line, want);
}

static void rejects_are_one_reason_each(void)
{
	char row[QUOTE_ROW_MAX + 1], line[QUOTE_LINE_MAX];
	struct quote q;

	row_line("", line, sizeof(line));
	EXPECT_STREQ(line, "{\"ok\":0,\"reason\":\"malformed\"}");

	quote_init(&q);
	q.signer_is_plain_name = true;
	quote_sign(&q);
	quote_row(&q, row, sizeof(row));
	row_line(row, line, sizeof(line));
	EXPECT_STREQ(line, "{\"ok\":0,\"reason\":\"bad_signature\"}");

	quote_init(&q);
	quote_sign(&q);
	q.body_sha256[0] = q.body_sha256[0] == '0' ? '1' : '0';
	quote_row(&q, row, sizeof(row));
	row_line(row, line, sizeof(line));
	EXPECT_STREQ(line, "{\"ok\":0,\"reason\":\"body_mismatch\"}");
}

static void changed_attest_or_signature_is_a_bad_signature(void)
{
	struct quote q;

	quote_init(&q);
	quote_sign(&q);
	q.attest[ATTEST_CLOCK_OFF + 7] ^= 0x01;
	EXPECT_EQ(quote_verdict(&q), QUOTE_BAD_SIGNATURE);

	quote_init(&q);
	quote_sign(&q);
	q.sig[SIG_R_OFF + 31] ^= 0x01;
	EXPECT_EQ(quote_verdict(&q), QUOTE_BAD_SIGNATURE);

	quote_init(&q);
	quote_sign(&q);
	q.sig[SIG_S_OFF + 31] ^= 0x01;
	EXPECT_EQ(quote_verdict(&q), QUOTE_BAD_SIGNATURE);
}

static void changed_magic_or_signature_header_is_malformed(void)
{
	struct quote q;

	quote_init(&q);
	quote_sign(&q);
	q.attest[ATTEST_MAGIC_OFF] ^= 0x01;
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);

	quote_init(&q);
	quote_sign(&q);
	q.sig[SIG_ALG_OFF + 1] ^= 0x01;
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);
}

static void other_body_sha256_is_a_body_mismatch(void)
{
	struct quote q;

	quote_init(&q);
	quote_sign(&q);
	q.body_sha256[63] = q.body_sha256[63] == 'f' ? 'e' : 'f';
	EXPECT_EQ(quote_verdict(&q), QUOTE_BODY_MISMATCH);
}

static void signed_extra_of_another_body_is_a_body_mismatch(void)
{
	struct quote q;

	quote_init(&q);
	q.extra[0] ^= 0x01;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_BODY_MISMATCH);

	quote_init(&q);
	q.extra_len = 20;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_BODY_MISMATCH);

	quote_init(&q);
	q.extra_len = 0;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_BODY_MISMATCH);
}

static void plain_name_as_signer_is_a_bad_signature(void)
{
	struct quote q;

	quote_init(&q);
	q.signer_is_plain_name = true;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_BAD_SIGNATURE);
}

static void quote_over_pcrs_is_malformed(void)
{
	struct quote q;

	quote_init(&q);
	q.pcr_mask = 1U << 9 | 1U << 11;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);

	quote_init(&q);
	q.pcr_mask = 1U << 23;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);
}

static void nv_certification_is_malformed(void)
{
	struct quote q;

	quote_init(&q);
	q.certifies_nv = true;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);
}

static void key_that_is_not_p256_ecdsa_is_malformed(void)
{
	struct quote q;

	quote_init(&q);
	q.ak.curve = TPM_ECC_NIST_P384;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);

	quote_init(&q);
	q.ak.scheme = TPM_ALG_NULL;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);

	quote_init(&q);
	q.ak.type = TPM_ALG_RSA;
	q.ak.scheme = TPM_ALG_NULL;
	q.ak.rsa_bits = 2048;
	q.ak.n_len = 256;
	q.ak.n[0] = 0x80;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_MALFORMED);
}

static void key_off_the_curve_is_a_bad_signature(void)
{
	struct quote q;

	quote_init(&q);
	q.ak.x[31] ^= 0x01;
	quote_sign(&q);
	EXPECT_EQ(quote_verdict(&q), QUOTE_BAD_SIGNATURE);
}

/* Each of the three base64 fields, by the tabs before it. */
static char *row_field(char *row, int tabs)
{
	while (tabs--)
		row = strchr(row, '\t') + 1;
	return row;
}

static void base64_that_is_not_standard_is_malformed(void)
{
	char row[QUOTE_ROW_MAX + 2], *pad;
	struct quote q;
	int field;

	quote_init(&q);
	quote_sign(&q);
	quote_row(&q, row, sizeof(row));
	ASSERT_EQ(row_verdict(row), QUOTE_OK);

	for (field = 0; field < 3; field++) {
		char *text = row_field(row, field), was = *text;

		*text = '*';
		EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);
		*text = ' ';
		EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);
		*text = '-';
		EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);
		*text = was;
	}
	ASSERT_EQ(row_verdict(row), QUOTE_OK);

	/* The signature is 72 bytes, so nothing pads it: cut one digit. */
	pad = row_field(row, 2) - 2;
	memmove(pad, pad + 1, strlen(pad));
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);

	quote_row(&q, row, sizeof(row));
	pad = row_field(row, 2) - 1;
	memmove(pad + 1, pad, strlen(pad) + 1);
	*pad = '\n';
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);

	/*
	 * The key is 88 bytes: its last digit holds two bits of it and
	 * four that a decoder drops, so the next digit decodes the same.
	 */
	quote_row(&q, row, sizeof(row));
	pad = strchr(row_field(row, 2), '=');
	ASSERT_TRUE(pad && pad[1] == '=' && pad[2] == '\t');
	pad[-1]++;
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);
}

static void row_that_does_not_split_is_malformed(void)
{
	char row[QUOTE_ROW_MAX + 8], *tab;
	struct quote q;
	size_t len;

	quote_init(&q);
	quote_sign(&q);
	quote_row(&q, row, sizeof(row));
	len = strlen(row);

	row[len] = '\t';
	row[len + 1] = '\0';
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);
	row[len] = '\n';
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);
	row[len - 1] = '\0';
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);

	quote_row(&q, row, sizeof(row));
	row[len - 1] = 'g';
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);

	quote_row(&q, row, sizeof(row));
	tab = strchr(row, '\t');
	*tab = ' ';
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);

	EXPECT_EQ(row_verdict(""), QUOTE_MALFORMED);
	EXPECT_EQ(row_verdict("\t\t\t"), QUOTE_MALFORMED);
	EXPECT_EQ(row_verdict("\t\t\t\t"), QUOTE_MALFORMED);
}

static void field_longer_than_its_structure_is_malformed(void)
{
	char row[BASE64_LEN(TPM_ATTEST_MAX) + 8 + QUOTE_ROW_MAX];
	char one[QUOTE_ROW_MAX + 1], *rest;
	struct quote q;

	quote_init(&q);
	quote_sign(&q);
	quote_row(&q, one, sizeof(one));
	rest = strchr(one, '\t');
	memset(row, 'A', BASE64_LEN(TPM_ATTEST_MAX) + 4);
	ASSERT_TRUE(strscpy(row + BASE64_LEN(TPM_ATTEST_MAX) + 4, rest,
			    sizeof(row) - BASE64_LEN(TPM_ATTEST_MAX) - 4) > 0);
	EXPECT_EQ(row_verdict(row), QUOTE_MALFORMED);
}

static void otel_row_format(const struct quote *q, const char *ak_name_override,
			    char *row, size_t cap)
{
	char attest_hex[QUOTE_ATTEST_HEX_MAX + 1];
	char sig_hex[QUOTE_SIG_HEX_MAX + 1];
	char ak_name[QUOTE_AK_NAME_HEX_LEN + 1];
	char ak_hex[QUOTE_AK_HEX_MAX + 1];

	hex_encode(q->ak_name, sizeof(q->ak_name), ak_name);
	hex_encode(q->attest, q->attest_len, attest_hex);
	hex_encode(q->sig, sizeof(q->sig), sig_hex);
	hex_encode(q->ak_public, q->ak_public_len, ak_hex);
	ASSERT_TRUE(strsprintf(row, cap, "%s\t%s\t%s\t%s\t%s",
			       ak_name_override ? ak_name_override : ak_name,
			       attest_hex, sig_hex, ak_hex,
			       q->body_sha256) > 0);
}

static void otel_envelope_row_is_verified(void)
{
	static const char otel_body[] = "{\"resourceLogs\":[]}";
	char row[QUOTE_OTEL_ROW_MAX + 1], line[QUOTE_LINE_MAX];
	char wrong_name[QUOTE_AK_NAME_HEX_LEN + 1];
	__u8 body_digest[CRYPTO_SHA256_LEN];
	struct quote_result res;
	struct quote q;

	quote_init(&q);
	ASSERT_EQ(sha256_buffer(otel_body, strlen(otel_body), body_digest), 0);
	hex_encode(body_digest, sizeof(body_digest), q.body_sha256);
	ASSERT_EQ(otel_origin_digest(body_digest, q.extra), 0);
	q.extra_len = CRYPTO_SHA256_LEN;
	quote_sign(&q);

	otel_row_format(&q, NULL, row, sizeof(row));
	ASSERT_EQ(quote_otel_row_check(row, strlen(row), &res), 0);
	ASSERT_EQ(res.verdict, QUOTE_OK);
	EXPECT_UEQ(res.reset_count, QUOTE_RESET_COUNT);
	EXPECT_UEQ(res.restart_count, QUOTE_RESTART_COUNT);
	EXPECT_UEQ(res.clock, QUOTE_CLOCK);
	ASSERT_EQ(quote_row_emit(&res, line, sizeof(line)), 0);
	EXPECT_TRUE(str_contains(line, "\"restart_count\":3"));

	/* Tampered body_sha256 fails origin check. */
	q.body_sha256[0] = q.body_sha256[0] == '0' ? '1' : '0';
	otel_row_format(&q, NULL, row, sizeof(row));
	ASSERT_EQ(quote_otel_row_check(row, strlen(row), &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_BODY_MISMATCH);

	/* Claimed AK name mismatch fails signature check. */
	hex_encode(q.ak_name, sizeof(q.ak_name), wrong_name);
	wrong_name[QUOTE_AK_NAME_HEX_LEN - 1] =
		wrong_name[QUOTE_AK_NAME_HEX_LEN - 1] == '0' ? '1' : '0';
	otel_row_format(&q, wrong_name, row, sizeof(row));
	ASSERT_EQ(quote_otel_row_check(row, strlen(row), &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_BAD_SIGNATURE);

	/* Non-hex AK is rejected as malformed. */
	otel_row_format(&q, NULL, row, sizeof(row));
	row[strlen(row) - QUOTE_BODY_HEX_LEN - 2] = 'Z';
	ASSERT_EQ(quote_otel_row_check(row, strlen(row), &res), 0);
	EXPECT_EQ(res.verdict, QUOTE_MALFORMED);
}

static const struct unit_case cases[] = {
	UNIT_CASE(good_row_is_accepted),
	UNIT_CASE(rejects_are_one_reason_each),
	UNIT_CASE(changed_attest_or_signature_is_a_bad_signature),
	UNIT_CASE(changed_magic_or_signature_header_is_malformed),
	UNIT_CASE(other_body_sha256_is_a_body_mismatch),
	UNIT_CASE(signed_extra_of_another_body_is_a_body_mismatch),
	UNIT_CASE(plain_name_as_signer_is_a_bad_signature),
	UNIT_CASE(quote_over_pcrs_is_malformed),
	UNIT_CASE(nv_certification_is_malformed),
	UNIT_CASE(key_that_is_not_p256_ecdsa_is_malformed),
	UNIT_CASE(key_off_the_curve_is_a_bad_signature),
	UNIT_CASE(base64_that_is_not_standard_is_malformed),
	UNIT_CASE(row_that_does_not_split_is_malformed),
	UNIT_CASE(field_longer_than_its_structure_is_malformed),
	UNIT_CASE(otel_envelope_row_is_verified),
	{}
};

UNIT_SUITE(quote_check, cases);
