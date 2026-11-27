// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <shirudo/byteorder.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "ek_cloud.h"
#include "unit.h"

struct spki_blobs {
	char	pem[2048];
	size_t	pem_len;
	__u8	der[1024];
	size_t	der_len;
	char	der_b64[2048];
};

static void make_spki(EVP_PKEY *pkey, struct spki_blobs *out)
{
	__u8 *p = out->der;
	char *mem = NULL;
	int der_len;
	BIO *bio;
	long n;

	memset(out, 0, sizeof(*out));
	der_len = i2d_PUBKEY(pkey, &p);
	ASSERT_TRUE(der_len > 0 && (size_t)der_len <= sizeof(out->der));
	out->der_len = (size_t)der_len;
	ASSERT_EQ(base64_encode(out->der, out->der_len, out->der_b64,
				sizeof(out->der_b64)), 0);

	bio = BIO_new(BIO_s_mem());
	ASSERT_TRUE(bio);
	ASSERT_EQ(PEM_write_bio_PUBKEY(bio, pkey), 1);
	n = BIO_get_mem_data(bio, &mem);
	ASSERT_TRUE(n > 0 && (size_t)n < sizeof(out->pem));
	memcpy(out->pem, mem, (size_t)n);
	out->pem[n] = '\0';
	out->pem_len = (size_t)n;
	BIO_free(bio);
}

static void rsa2048_vectors_across_cloud_formats(void)
{
	__u8 tpmt_l1[TPM_PUBLIC_MAX], tpmt_l2[TPM_PUBLIC_MAX];
	__u8 tpm2b[2 + TPM_PUBLIC_MAX], tampered[2 + TPM_PUBLIC_MAX];
	__u8 name_pem[TPM_NAME_MAX], name_der[TPM_NAME_MAX];
	__u8 name_b64_der[TPM_NAME_MAX], name_tpm2b[TPM_NAME_MAX];
	__u8 name_b64_tpm2b[TPM_NAME_MAX], name_l2[TPM_NAME_MAX];
	__u8 vname[TPM_NAME_MAX];
	char b64_tpm2b[2048], b64_wrapped[2200];
	size_t len_l1 = 0, len_l2 = 0, tpm2b_len, vlen = 0, off = 0, i;
	enum ek_template used_tmpl = EK_TEMPLATE_POLICY_B;
	struct ek_cloud_key parsed;
	struct tpm_public pub_l1, pub_l2;
	struct spki_blobs spki, other_spki;
	EVP_PKEY *pkey, *other;
	bool rsa = false;

	pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
	other = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
	ASSERT_TRUE(pkey && other);
	make_spki(pkey, &spki);
	make_spki(other, &other_spki);

	/* GCP PEM SPKI, AWS/Azure DER SPKI and base64 DER SPKI. */
	ASSERT_EQ(ek_cloud_parse(spki.pem, spki.pem_len, &parsed), 0);
	EXPECT_EQ(parsed.format, EK_CLOUD_SPKI);
	EXPECT_TRUE(parsed.rsa);
	EXPECT_EQ(parsed.n_len, 256U);
	EXPECT_EQ(parsed.e, 65537U);

	ASSERT_EQ(ek_cloud_build_public(&parsed, EK_TEMPLATE_POLICY_A, &pub_l1,
					tpmt_l1, &len_l1, name_pem), 0);
	ASSERT_EQ(ek_cloud_build_public(&parsed, EK_TEMPLATE_POLICY_B, &pub_l2,
					tpmt_l2, &len_l2, name_l2), 0);
	EXPECT_TRUE(ek_low_range_template_valid(&pub_l1));
	EXPECT_FALSE(ek_low_range_template_valid(&pub_l2));
	EXPECT_EQ(name_pem[0], 0x00);
	EXPECT_EQ(name_pem[1], 0x0b);
	EXPECT_TRUE(memcmp(name_pem, name_l2, TPM_NAME_LEN) != 0);

	ASSERT_EQ(ek_cloud_parse(spki.der, spki.der_len, &parsed), 0);
	ASSERT_EQ(ek_cloud_name(&parsed, EK_TEMPLATE_POLICY_A,
				false, &rsa, &used_tmpl, name_der), 0);
	EXPECT_TRUE(rsa);
	EXPECT_EQ(used_tmpl, EK_TEMPLATE_POLICY_A);
	EXPECT_EQ(memcmp(name_pem, name_der, TPM_NAME_LEN), 0);

	ASSERT_EQ(ek_cloud_parse(spki.der_b64, strlen(spki.der_b64), &parsed),
		  0);
	ASSERT_EQ(ek_cloud_name(&parsed, EK_TEMPLATE_POLICY_A, false, NULL,
				NULL, name_b64_der), 0);
	EXPECT_EQ(memcmp(name_pem, name_b64_der, TPM_NAME_LEN), 0);

	/* Raw and line-wrapped base64 TPM2B_PUBLIC (AWS NitroTPM / Azure). */
	tpm2b_len = tpm_put2b(tpm2b, tpmt_l1, len_l1);
	ASSERT_EQ(ek_cloud_parse(tpm2b, tpm2b_len, &parsed), 0);
	ASSERT_EQ(ek_cloud_name(&parsed, EK_TEMPLATE_POLICY_A, false,
				&rsa, &used_tmpl, name_tpm2b), 0);
	EXPECT_TRUE(rsa);
	EXPECT_EQ(used_tmpl, EK_TEMPLATE_POLICY_A);
	EXPECT_EQ(memcmp(name_pem, name_tpm2b, TPM_NAME_LEN), 0);

	ASSERT_EQ(base64_encode(tpm2b, tpm2b_len, b64_tpm2b, sizeof(b64_tpm2b)),
		  0);
	for (i = 0; b64_tpm2b[i]; i++) {
		if (i && (i % 64) == 0)
			b64_wrapped[off++] = '\n';
		b64_wrapped[off++] = b64_tpm2b[i];
	}
	b64_wrapped[off++] = '\n';
	b64_wrapped[off] = '\0';
	ASSERT_EQ(ek_cloud_parse(b64_wrapped, off, &parsed), 0);
	ASSERT_EQ(ek_cloud_name(&parsed, EK_TEMPLATE_POLICY_A, false,
				NULL, NULL, name_b64_tpm2b), 0);
	EXPECT_EQ(memcmp(name_pem, name_b64_tpm2b, TPM_NAME_LEN), 0);

	/* Presented verification accepts both L-1 and L-2 against SPKI. */
	{
		struct ek_cloud_key other_parsed;

		ASSERT_EQ(ek_cloud_parse(spki.pem, spki.pem_len, &parsed), 0);
		ASSERT_EQ(ek_cloud_parse(other_spki.pem, other_spki.pem_len,
					 &other_parsed), 0);
		ASSERT_EQ(ek_cloud_verify_presented(&parsed, tpm2b, tpm2b_len,
						    vname, &vlen), 0);
		EXPECT_EQ(vlen, TPM_NAME_LEN);
		EXPECT_EQ(memcmp(vname, name_pem, TPM_NAME_LEN), 0);

		tpm2b_len = tpm_put2b(tpm2b, tpmt_l2, len_l2);
		ASSERT_EQ(ek_cloud_verify_presented(&parsed, tpm2b, tpm2b_len,
						    vname, &vlen), 0);
		EXPECT_EQ(vlen, TPM_NAME_LEN);
		EXPECT_EQ(memcmp(vname, name_l2, TPM_NAME_LEN), 0);

		/* Tampered modulus or different RSA key is refused. */
		memcpy(tampered, tpm2b, tpm2b_len);
		tampered[tpm2b_len - 1] ^= 0x02;
		EXPECT_EQ(ek_cloud_verify_presented(&parsed, tampered,
						    tpm2b_len, vname, &vlen),
			  -EKEYREJECTED);
		EXPECT_EQ(ek_cloud_verify_presented(&other_parsed, tpm2b,
						    tpm2b_len, vname, &vlen),
			  -EKEYREJECTED);
	}

	EVP_PKEY_free(other);
	EVP_PKEY_free(pkey);
}

static void ecc_p256_vectors_and_tamper_rejection(void)
{
	__u8 tpmt_l1[TPM_PUBLIC_MAX], tpmt_l2[TPM_PUBLIC_MAX];
	__u8 tpm2b[2 + TPM_PUBLIC_MAX], bad_tpm2b[2 + TPM_PUBLIC_MAX];
	__u8 name_l1[TPM_NAME_MAX], name_l2[TPM_NAME_MAX], vname[TPM_NAME_MAX];
	size_t len_l1 = 0, len_l2 = 0, tpm2b_len, bad_len = 0, vlen = 0;
	struct ek_cloud_key parsed, other_parsed, tpm2b_parsed;
	struct tpm_public pub_l1, pub_l2, bad_pub;
	struct spki_blobs spki, other_spki;
	char b64_l2[1024];
	enum ek_template used_tmpl = EK_TEMPLATE_POLICY_A;
	EVP_PKEY *pkey, *other;

	pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	other = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	ASSERT_TRUE(pkey && other);
	make_spki(pkey, &spki);
	make_spki(other, &other_spki);

	ASSERT_EQ(ek_cloud_parse(spki.pem, spki.pem_len, &parsed), 0);
	ASSERT_EQ(ek_cloud_parse(other_spki.der, other_spki.der_len,
				 &other_parsed), 0);
	EXPECT_FALSE(parsed.rsa);

	ASSERT_EQ(ek_cloud_build_public(&parsed, EK_TEMPLATE_POLICY_A, &pub_l1,
					tpmt_l1, &len_l1, name_l1), 0);
	ASSERT_EQ(ek_cloud_build_public(&parsed, EK_TEMPLATE_POLICY_B, &pub_l2,
					tpmt_l2, &len_l2, name_l2), 0);

	tpm2b_len = tpm_put2b(tpm2b, tpmt_l2, len_l2);
	ASSERT_EQ(base64_encode(tpm2b, tpm2b_len, b64_l2, sizeof(b64_l2)), 0);
	ASSERT_EQ(ek_cloud_parse(b64_l2, strlen(b64_l2), &tpm2b_parsed), 0);
	ASSERT_EQ(ek_cloud_name(&tpm2b_parsed, EK_TEMPLATE_POLICY_A,
				false, NULL, &used_tmpl, vname), 0);
	EXPECT_EQ(used_tmpl, EK_TEMPLATE_POLICY_B);
	EXPECT_EQ(memcmp(vname, name_l2, TPM_NAME_LEN), 0);

	/* Cloud TPM2B_PUBLIC pins the exact template as well as the point. */
	EXPECT_EQ(ek_cloud_verify_presented(&tpm2b_parsed,
					    tpmt_l1, len_l1, vname, &vlen),
		  -EKEYREJECTED);
	ASSERT_EQ(ek_cloud_verify_presented(&tpm2b_parsed,
					    tpmt_l2, len_l2, vname, &vlen), 0);

	/* Different valid P-256 point is rejected. */
	bad_pub = pub_l1;
	memcpy(bad_pub.x, other_parsed.x, 32);
	memcpy(bad_pub.y, other_parsed.y, 32);
	ASSERT_EQ(tpm_public_marshal(&bad_pub, bad_tpm2b + 2, TPM_PUBLIC_MAX,
				     &bad_len), 0);
	put_be16(bad_tpm2b, (__u16)bad_len);
	EXPECT_EQ(ek_cloud_verify_presented(&parsed,
					    bad_tpm2b, 2 + bad_len, vname,
					    &vlen), -EKEYREJECTED);

	/* Non-EK attribute (sign bit set) is rejected. */
	bad_pub = pub_l1;
	bad_pub.attrs |= TPM_ATTR_SIGN_ENCRYPT;
	ASSERT_EQ(tpm_public_marshal(&bad_pub, bad_tpm2b + 2, TPM_PUBLIC_MAX,
				     &bad_len), 0);
	put_be16(bad_tpm2b, (__u16)bad_len);
	EXPECT_EQ(ek_cloud_parse(bad_tpm2b, 2 + bad_len, &tpm2b_parsed),
		  -EKEYREJECTED);
	EXPECT_EQ(ek_cloud_verify_presented(&parsed,
					    bad_tpm2b, 2 + bad_len, vname,
					    &vlen), -EKEYREJECTED);

	/* Missing restricted attribute is rejected. */
	bad_pub = pub_l1;
	bad_pub.attrs &= ~0x00010000u;
	ASSERT_EQ(tpm_public_marshal(&bad_pub, bad_tpm2b + 2, TPM_PUBLIC_MAX,
				     &bad_len), 0);
	put_be16(bad_tpm2b, (__u16)bad_len);
	EXPECT_EQ(ek_cloud_parse(bad_tpm2b, 2 + bad_len, &tpm2b_parsed),
		  -EKEYREJECTED);

	/* Null symmetric protector (not AES-128-CFB) is rejected. */
	bad_pub = pub_l1;
	bad_pub.sym_alg = TPM_ALG_NULL;
	ASSERT_EQ(tpm_public_marshal(&bad_pub, bad_tpm2b + 2, TPM_PUBLIC_MAX,
				     &bad_len), 0);
	put_be16(bad_tpm2b, (__u16)bad_len);
	EXPECT_EQ(ek_cloud_parse(bad_tpm2b, 2 + bad_len, &tpm2b_parsed),
		  -EKEYREJECTED);

	/* Unapproved authPolicy is rejected. */
	bad_pub = pub_l1;
	bad_pub.policy[0] ^= 0xff;
	ASSERT_EQ(tpm_public_marshal(&bad_pub, bad_tpm2b + 2, TPM_PUBLIC_MAX,
				     &bad_len), 0);
	put_be16(bad_tpm2b, (__u16)bad_len);
	EXPECT_EQ(ek_cloud_parse(bad_tpm2b, 2 + bad_len, &tpm2b_parsed),
		  -EKEYREJECTED);

	/* PolicyB (L-2) without userWithAuth, or PolicyA (L-1) with it, is rejected. */
	bad_pub = pub_l2;
	bad_pub.attrs = TPM_EK_ATTRS;
	EXPECT_FALSE(ek_cloud_template_valid(&bad_pub));
	ASSERT_EQ(tpm_public_marshal(&bad_pub, bad_tpm2b + 2, TPM_PUBLIC_MAX,
				     &bad_len), 0);
	put_be16(bad_tpm2b, (__u16)bad_len);
	EXPECT_EQ(ek_cloud_parse(bad_tpm2b, 2 + bad_len, &tpm2b_parsed),
		  -EKEYREJECTED);
	EXPECT_EQ(ek_cloud_verify_presented(&parsed,
					    bad_tpm2b, 2 + bad_len, vname,
					    &vlen), -EKEYREJECTED);

	bad_pub = pub_l1;
	bad_pub.attrs |= TPM_ATTR_USER_WITH_AUTH;
	EXPECT_FALSE(ek_cloud_template_valid(&bad_pub));

	EVP_PKEY_free(other);
	EVP_PKEY_free(pkey);
}

static void unsupported_algorithms_and_malformed_inputs_fail(void)
{
	struct ek_cloud_key parsed;
	struct spki_blobs spki;
	__u8 junk[64] = { 0x30, 0x05, 0x01, 0x02, 0x03 };
	EVP_PKEY *rsa3072, *p384;

	rsa3072 = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)3072);
	p384 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
	ASSERT_TRUE(rsa3072 && p384);

	make_spki(rsa3072, &spki);
	EXPECT_EQ(ek_cloud_parse(spki.pem, spki.pem_len, &parsed),
		  -EPROTONOSUPPORT);
	EXPECT_EQ(ek_cloud_parse(spki.der, spki.der_len, &parsed),
		  -EPROTONOSUPPORT);

	make_spki(p384, &spki);
	EXPECT_EQ(ek_cloud_parse(spki.der, spki.der_len, &parsed),
		  -EPROTONOSUPPORT);

	EXPECT_EQ(ek_cloud_parse(NULL, 10, &parsed), -EINVAL);
	EXPECT_EQ(ek_cloud_parse(junk, 0, &parsed), -EINVAL);
	EXPECT_EQ(ek_cloud_parse(junk, sizeof(junk), &parsed), -EINVAL);
	EXPECT_EQ(ek_cloud_parse("not-base64!", 11, &parsed), -EINVAL);

	EVP_PKEY_free(p384);
	EVP_PKEY_free(rsa3072);
}

/*
 * The endorsement key of an Azure Trusted Launch vTPM, as tpm2_readpublic
 * printed it for the persistent handle 0x81010001, and the name the TPM
 * gave for it.
 */
static const char azure_ek_pem[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqpsgzgAAM6Uc+wFTGGHt\n"
	"9Pfg4ZBMZXyfQ81JZHzuXJtxZH0B4Cs6eOnMVvyuLDQpLh8oOJGKTP2dJSLxXoeF\n"
	"tQhk+APDI/ZywVgbN6xJsJFi1+XGkjprUFUBu3ACTCQvjnIlnv+rQ8hHtGe0GgTF\n"
	"zUy7MxEOo7D63C6hftrL9Wwq5RZFT/EXDMZ3DaXGj7dQb0+OIKQ8vyO4ZJGz2PJV\n"
	"6zFr8YwpYVsf4jRU/s5wySGn09lBUbgH1h5YFU76PqeDFXL5n/uk+qNtWlZKMIQt\n"
	"Oh908kHc4qAlcKlyOvIfmacuQysR1hG4WoFgJlWqSHZByeGkBuprs/kLytepu3d9\n"
	"SQIDAQAB\n"
	"-----END PUBLIC KEY-----\n";

static const __u8 azure_ek_name[TPM_NAME_LEN] = {
	0x00, 0x0b, 0x1e, 0xad, 0x9b, 0xe3, 0x6c, 0x74, 0xac, 0x17, 0x98,
	0x96, 0x43, 0x95, 0xfa, 0x3c, 0x35, 0xef, 0x88, 0x28, 0x23, 0x10,
	0x26, 0xc8, 0x01, 0x12, 0x8c, 0x1e, 0xc8, 0xf6, 0x98, 0x08, 0x74,
	0xe0,
};

/* TCG EK Credential Profile PolicyCSHA256 (TPM2_PolicyAuthorizeNV). */
static const __u8 tcg_policy_c_sha256[TPM_DIGEST_LEN] = {
	0x37, 0x67, 0xe2, 0xed, 0xd4, 0x3f, 0xf4, 0x5a, 0x3a, 0x7e, 0x1e,
	0xae, 0xfc, 0xef, 0x78, 0x64, 0x3d, 0xca, 0x96, 0x46, 0x32, 0xe7,
	0xaa, 0xd8, 0x2c, 0x67, 0x3a, 0x30, 0xd8, 0x63, 0x3f, 0xde,
};

static void name_of_a_real_vtpm_key_and_the_tcg_policies(void)
{
	__u8 name[TPM_NAME_MAX], derived_policy_b[TPM_DIGEST_LEN];
	enum ek_template tmpl = EK_TEMPLATE_POLICY_B;
	struct ek_cloud_key azure_key;
	bool rsa = false;

	ASSERT_EQ(ek_cloud_parse(azure_ek_pem, sizeof(azure_ek_pem) - 1,
				 &azure_key), 0);
	ASSERT_EQ(ek_cloud_name(&azure_key, EK_TEMPLATE_POLICY_A, false,
				&rsa, &tmpl, name), 0);
	EXPECT_TRUE(rsa);
	EXPECT_EQ(tmpl, EK_TEMPLATE_POLICY_A);
	EXPECT_EQ(memcmp(name, azure_ek_name, TPM_NAME_LEN), 0);

	ASSERT_EQ(tpm_policy_or(shirudo_tpm_ek_policy, tcg_policy_c_sha256,
				derived_policy_b), 0);
	EXPECT_EQ(memcmp(shirudo_tpm_ek_policy_b, derived_policy_b,
			 TPM_DIGEST_LEN), 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(name_of_a_real_vtpm_key_and_the_tcg_policies),
	UNIT_CASE(rsa2048_vectors_across_cloud_formats),
	UNIT_CASE(ecc_p256_vectors_and_tamper_rejection),
	UNIT_CASE(unsupported_algorithms_and_malformed_inputs_fail),
	{}
};

UNIT_SUITE(ek_cloud, cases);
