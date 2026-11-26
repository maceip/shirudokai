// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <shirudo/string.h>

#include "attest.h"
#include "ek_cloud.h"
#include "hex.h"
#include "malloc.h"
#include "unit.h"

#define EVIDENCE "fuzz/corpus/attest/snapshot"

static void pcrs_are_a_list_up_to_23(void)
{
	__u32 mask;

	ASSERT_EQ(attest_parse_pcrs("0", &mask), 0);
	EXPECT_EQ(mask, 1U);
	ASSERT_EQ(attest_parse_pcrs("0,9,23", &mask), 0);
	EXPECT_EQ(mask, 1U | 1U << 9 | 1U << 23);
	ASSERT_EQ(attest_parse_pcrs("9,9", &mask), 0);
	EXPECT_EQ(mask, 1U << 9);
	EXPECT_EQ(attest_parse_pcrs("", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("24", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1,,2", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs(",1", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1,", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1,2,", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1 ", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("+1", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("0x1", &mask), -EINVAL);
}

static void pcr_value_is_a_pcr_and_an_equals(void)
{
	const char *value;
	__u64 pcr;

	ASSERT_EQ(attest_parse_pcr_value("15=ab", &pcr, &value), 0);
	EXPECT_EQ(pcr, 15);
	EXPECT_STREQ(value, "ab");
	ASSERT_EQ(attest_parse_pcr_value("0=", &pcr, &value), 0);
	EXPECT_STREQ(value, "");
	EXPECT_EQ(attest_parse_pcr_value("24=ab", &pcr, &value), -EINVAL);
	EXPECT_EQ(attest_parse_pcr_value("=ab", &pcr, &value), -EINVAL);
	EXPECT_EQ(attest_parse_pcr_value("15", &pcr, &value), -EINVAL);
	EXPECT_EQ(attest_parse_pcr_value("1 5=ab", &pcr, &value), -EINVAL);
}

#define D64 "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

static void name_digest_is_a_name_and_64_digits(void)
{
	char name[UPATCH_NAME_MAX + 1], longest[UPATCH_NAME_MAX + 3 + 64];
	__u8 digest[32];

	ASSERT_EQ(attest_parse_name_digest("fix=" D64, name, digest), 0);
	EXPECT_STREQ(name, "fix");
	EXPECT_EQ(digest[1], 0x11);
	ASSERT_EQ(attest_parse_name_digest("a:b=" D64, name, digest), 0);
	EXPECT_STREQ(name, "a:b");
	EXPECT_EQ(attest_parse_name_digest("=" D64, name, digest), -EINVAL);
	EXPECT_EQ(attest_parse_name_digest("fix" D64, name, digest), -EINVAL);
	EXPECT_EQ(attest_parse_name_digest("fix=" D64 "0", name, digest),
		  -EINVAL);
	EXPECT_EQ(attest_parse_name_digest("fix==" D64, name, digest),
		  -EINVAL);
	memset(longest, 'n', UPATCH_NAME_MAX);
	ASSERT_TRUE(strscpy(longest + UPATCH_NAME_MAX, "=" D64,
			    sizeof(longest) - UPATCH_NAME_MAX) > 0);
	EXPECT_EQ(attest_parse_name_digest(longest, name, digest), 0);
	EXPECT_EQ(strlen(name), UPATCH_NAME_MAX);
	memset(longest, 'n', UPATCH_NAME_MAX + 1);
	ASSERT_TRUE(strscpy(longest + UPATCH_NAME_MAX + 1, "=" D64,
			    sizeof(longest) - UPATCH_NAME_MAX - 1) > 0);
	EXPECT_EQ(attest_parse_name_digest(longest, name, digest), -EINVAL);
}

/* make -C testing runs from testing/, and by hand from the top of the tree. */
static char *read_evidence(size_t *len)
{
	static char buf[1 << 16];
	FILE *f = fopen(EVIDENCE, "r");

	if (!f)
		f = fopen("testing/" EVIDENCE, "r");
	ASSERT_TRUE(f);
	*len = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	return buf;
}

static void report_ends_its_last_line_at_any_size(void)
{
	static const __u8 nonce[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	struct attest_expect expect = {
		.nonce = nonce,
		.nonce_len = sizeof(nonce),
	};
	static char report[ATTEST_REPORT_MAX];
	size_t len, full, cap, n;
	const char *doc;

	doc = read_evidence(&len);
	ASSERT_EQ(attest_verify(doc, len, &expect, report, sizeof(report)),
		  -EKEYREJECTED);
	full = strlen(report);
	ASSERT_TRUE(full && report[full - 1] == '\n');
	for (cap = 1; cap <= full; cap++) {
		EXPECT_EQ(attest_verify(doc, len, &expect, report, cap),
			  -EKEYREJECTED);
		n = strlen(report);
		EXPECT_TRUE(n < cap);
		EXPECT_TRUE(!n || report[n - 1] == '\n');
	}
}

/* A record without a digest has none: it takes no digest from the last. */
static void record_without_digest_is_refused(void)
{
	static const __u8 nonce[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	struct attest_expect expect = {
		.nonce = nonce,
		.nonce_len = sizeof(nonce),
	};
	static const char key[] = "\"digest\":\"";
	static char doc[8192], report[ATTEST_REPORT_MAX];
	char *load, *digest = NULL, *at;
	const char *full;
	size_t len, cut;

	full = read_evidence(&len);
	ASSERT_TRUE(len < sizeof(doc));
	memcpy(doc, full, len);
	load = span_find(doc, len, "\"type\":\"upatch_load\"");
	ASSERT_TRUE(load);
	for (at = doc;
	     (at = span_find(at, len - (size_t)(at - doc), key)) && at < load;
	     at++)
		digest = at;
	ASSERT_TRUE(digest);
	cut = sizeof(key) - 1 + 64 + 2;
	memmove(digest, digest + cut, len - (size_t)(digest - doc) - cut);
	len -= cut;
	EXPECT_EQ(attest_verify(doc, len, &expect, report, sizeof(report)),
		  -EINVAL);
}

static size_t make_p256_pem(const __u8 x[32], const __u8 y[32], char *out,
			    size_t cap)
{
	EVP_PKEY_CTX *kctx;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM params[3];
	char *mem = NULL;
	__u8 point[65];
	BIO *bio;
	long n;

	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);
	params[0] = OSSL_PARAM_construct_utf8_string("group", (char *)"P-256",
						     0);
	params[1] = OSSL_PARAM_construct_octet_string("pub", point,
						      sizeof(point));
	params[2] = OSSL_PARAM_construct_end();
	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	ASSERT_TRUE(kctx);
	ASSERT_TRUE(EVP_PKEY_fromdata_init(kctx) > 0);
	ASSERT_TRUE(EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY,
				      params) > 0);
	EVP_PKEY_CTX_free(kctx);

	bio = BIO_new(BIO_s_mem());
	ASSERT_TRUE(bio);
	ASSERT_EQ(PEM_write_bio_PUBKEY(bio, pkey), 1);
	n = BIO_get_mem_data(bio, &mem);
	ASSERT_TRUE(n > 0 && (size_t)n < cap);
	memcpy(out, mem, (size_t)n);
	out[n] = '\0';
	BIO_free(bio);
	EVP_PKEY_free(pkey);
	return (size_t)n;
}

static void cloud_ek_pub_vouches_challenge_and_verify(void)
{
	static const __u8 nonce[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	static char doc[16384], report[ATTEST_REPORT_MAX];
	char pem[1024], wrong_pem[1024], ek_hex[2 * TPM_PUBLIC_MAX + 1];
	__u8 ek_raw[TPM_PUBLIC_MAX], cred[TPM_CREDENTIAL_LEN];
	struct attest_challenge_policy pol = {};
	struct attest_expect expect = {
		.nonce = nonce,
		.nonce_len = sizeof(nonce),
	};
	size_t len, pem_len, wrong_len, ek_len = 0, out_len = 0, out_cap = 0;
	char *ek_obj, *pub_key, *pub_end, *ek_cert, *cert_end, *chal = NULL;
	struct tpm_public pub;
	const char *full;
	EVP_PKEY *wrong;
	char *mem = NULL;
	BIO *bio;
	long n;

	full = read_evidence(&len);
	ASSERT_TRUE(len < sizeof(doc));
	memcpy(doc, full, len);

	ek_obj = span_find(doc, len, "\"ek\":{");
	ASSERT_TRUE(ek_obj);
	pub_key = span_find(ek_obj, len - (size_t)(ek_obj - doc),
			    "\"public\":\"");
	ASSERT_TRUE(pub_key);
	pub_key += sizeof("\"public\":\"") - 1;
	pub_end = memchr(pub_key, '"', len - (size_t)(pub_key - doc));
	ASSERT_TRUE(pub_end &&
		    (size_t)(pub_end - pub_key) < sizeof(ek_hex));
	memcpy(ek_hex, pub_key, (size_t)(pub_end - pub_key));
	ek_hex[pub_end - pub_key] = '\0';
	ASSERT_EQ(hex_decode_max(ek_hex, ek_raw, sizeof(ek_raw), &ek_len), 0);
	ASSERT_EQ(tpm_public_parse(ek_raw, ek_len, &pub), 0);
	ASSERT_EQ(pub.type, TPM_ALG_ECC);
	pem_len = make_p256_pem(pub.x, pub.y, pem, sizeof(pem));

	wrong = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	ASSERT_TRUE(wrong);
	bio = BIO_new(BIO_s_mem());
	ASSERT_TRUE(bio && PEM_write_bio_PUBKEY(bio, wrong) == 1);
	n = BIO_get_mem_data(bio, &mem);
	ASSERT_TRUE(n > 0 && (size_t)n < sizeof(wrong_pem));
	memcpy(wrong_pem, mem, (size_t)n);
	wrong_len = (size_t)n;
	BIO_free(bio);
	EVP_PKEY_free(wrong);

	/* Strip ek_certificate to null as on cloud vTPMs (AWS/GCP/Azure). */
	ek_cert = span_find(doc, len, "\"ek_certificate\":\"");
	if (ek_cert) {
		char *val = ek_cert + sizeof("\"ek_certificate\":") - 1;

		cert_end = memchr(val + 1, '"', len - (size_t)(val + 1 - doc));
		ASSERT_TRUE(cert_end);
		memcpy(val, "null", 4);
		memmove(val + 4, cert_end + 1,
			len - (size_t)(cert_end + 1 - doc));
		len -= (size_t)(cert_end + 1 - val) - 4;
	}

	/* Without --ek-pub or --trust-presented-ek, challenge refuses. */
	EXPECT_EQ(attest_challenge_make(doc, len, &pol, cred, &chal, &out_len,
					&out_cap, report, sizeof(report)),
		  -EKEYREJECTED);

	/* Matching --ek-pub vouches for the EK without --trust-presented-ek. */
	pol.ek_pub = pem;
	pol.ek_pub_len = pem_len;
	ASSERT_EQ(attest_challenge_make(doc, len, &pol, cred, &chal, &out_len,
					&out_cap, report, sizeof(report)), 0);
	EXPECT_TRUE(span_find(report, strlen(report),
			      "  OK    endorsement key: matches cloud public key\n") != NULL);
	xfree(chal, out_cap);
	chal = NULL;

	/* Wrong --ek-pub fails challenge. */
	pol.ek_pub = wrong_pem;
	pol.ek_pub_len = wrong_len;
	EXPECT_EQ(attest_challenge_make(doc, len, &pol, cred, &chal, &out_len,
					&out_cap, report, sizeof(report)),
		  -EKEYREJECTED);
	EXPECT_TRUE(span_find(report, strlen(report),
			      "  FAIL  endorsement key: matches cloud public key\n") != NULL);

	/* attest_verify checks --ek-pub and reports OK vs FAIL. */
	expect.have_ek_pub = true;
	expect.ek_pub = pem;
	expect.ek_pub_len = pem_len;
	EXPECT_EQ(attest_verify(doc, len, &expect, report, sizeof(report)),
		  -EKEYREJECTED);
	EXPECT_TRUE(span_find(report, strlen(report),
			      "  OK    endorsement key: matches cloud public key\n") != NULL);

	expect.ek_pub = wrong_pem;
	expect.ek_pub_len = wrong_len;
	EXPECT_EQ(attest_verify(doc, len, &expect, report, sizeof(report)),
		  -EKEYREJECTED);
	EXPECT_TRUE(span_find(report, strlen(report),
			      "  FAIL  endorsement key: matches cloud public key\n") != NULL);
}

static const struct unit_case cases[] = {
	UNIT_CASE(pcrs_are_a_list_up_to_23),
	UNIT_CASE(pcr_value_is_a_pcr_and_an_equals),
	UNIT_CASE(name_digest_is_a_name_and_64_digits),
	UNIT_CASE(report_ends_its_last_line_at_any_size),
	UNIT_CASE(record_without_digest_is_refused),
	UNIT_CASE(cloud_ek_pub_vouches_challenge_and_verify),
	{}
};

UNIT_SUITE(attest, cases);
