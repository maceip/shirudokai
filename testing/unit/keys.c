// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <shirudo/byteorder.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "keys.h"
#include "malloc.h"
#include "unit.h"

static struct trusted_set set;

static int make_cert_der(__s64 not_before, __s64 not_after,
			 EVP_PKEY **out_pkey, __u8 **out_der, size_t *out_len)
{
	EVP_PKEY *pkey = NULL;
	X509_NAME *name = NULL;
	ASN1_TIME *nb = NULL;
	ASN1_TIME *na = NULL;
	X509 *x509 = NULL;
	__u8 *der = NULL;
	int len, ret = -EINVAL;
	__u8 *p;

	pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
	x509 = pkey ? X509_new() : NULL;
	name = X509_NAME_new();
	nb = ASN1_TIME_set(NULL, (time_t)not_before);
	na = ASN1_TIME_set(NULL, (time_t)not_after);
	if (!pkey || !x509 || !name || !nb || !na)
		goto out;
	if (X509_set_version(x509, 2) != 1 ||
	    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1 ||
	    X509_set1_notBefore(x509, nb) != 1 ||
	    X509_set1_notAfter(x509, na) != 1 ||
	    X509_set_pubkey(x509, pkey) != 1 ||
	    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
				       (const __u8 *)"shirudo-test", -1, -1,
				       0) != 1 ||
	    X509_set_subject_name(x509, name) != 1 ||
	    X509_set_issuer_name(x509, name) != 1 ||
	    X509_sign(x509, pkey, NULL) <= 0)
		goto out;
	len = i2d_X509(x509, NULL);
	if (len <= 0)
		goto out;
	der = xmalloc((size_t)len);
	if (!der) {
		ret = -ENOMEM;
		goto out;
	}
	p = der;
	if (i2d_X509(x509, &p) != len) {
		xfree(der, (size_t)len);
		goto out;
	}
	*out_pkey = pkey;
	pkey = NULL;
	*out_der = der;
	*out_len = (size_t)len;
	ret = 0;
out:
	ASN1_TIME_free(na);
	ASN1_TIME_free(nb);
	X509_NAME_free(name);
	X509_free(x509);
	EVP_PKEY_free(pkey);
	return ret;
}

static int sign_detached_cms(EVP_PKEY *pkey, const __u8 *cert_der,
			     size_t cert_len, const __u8 *payload,
			     size_t payload_len, __u8 **out_sig,
			     size_t *out_len)
{
	const __u8 *cp = cert_der;
	CMS_ContentInfo *cms = NULL;
	X509 *x509 = NULL;
	BIO *in = NULL;
	__u8 *sig = NULL;
	int len, ret = -EINVAL;
	__u8 *p;

	x509 = d2i_X509(NULL, &cp, (long)cert_len);
	in = BIO_new_mem_buf(payload, (int)payload_len);
	if (!x509 || !in)
		goto out;
	cms = CMS_sign(NULL, NULL, NULL, NULL,
		       CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED |
		       CMS_STREAM);
	if (!cms ||
	    !CMS_add1_signer(cms, x509, pkey, EVP_sha512(),
			     CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP |
			     CMS_NO_SIGNING_TIME) ||
	    CMS_final(cms, in, NULL, CMS_NOCERTS | CMS_BINARY) != 1)
		goto out;
	len = i2d_CMS_ContentInfo(cms, NULL);
	if (len <= 0)
		goto out;
	sig = xmalloc((size_t)len);
	if (!sig) {
		ret = -ENOMEM;
		goto out;
	}
	p = sig;
	if (i2d_CMS_ContentInfo(cms, &p) != len) {
		xfree(sig, (size_t)len);
		goto out;
	}
	*out_sig = sig;
	*out_len = (size_t)len;
	ret = 0;
out:
	CMS_ContentInfo_free(cms);
	BIO_free(in);
	X509_free(x509);
	return ret;
}

static int write_raw(const char *path, const void *buf, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ssize_t n;

	if (fd < 0)
		return -errno;
	n = write(fd, buf, len);
	close(fd);
	return n == (ssize_t)len ? 0 : -EIO;
}

static void rm_rf(const char *dir)
{
	char cmd[512];

	if (strsprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir) >= 0)
		EXPECT_EQ(system(cmd), 0);
}

static void member_is_found_by_fingerprint(void)
{
	__u8 absent[32];

	memset(&set, 0, sizeof(set));
	set.n = 2;
	memset(set.certs[0].fingerprint, 0x11, 32);
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(absent, 0x33, sizeof(absent));

	EXPECT_TRUE(keys_member(&set, set.certs[1].fingerprint) ==
		    &set.certs[1]);
	EXPECT_TRUE(!keys_member(&set, absent));
}

/* Entries past n are a stale tail, not members. */
static void member_past_the_count_is_none(void)
{
	__u8 stale[32];

	memset(&set, 0, sizeof(set));
	set.n = 1;
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(stale, 0x22, sizeof(stale));

	EXPECT_TRUE(!keys_member(&set, stale));
}

static void cert_valid_at_enforces_validity_bounds(void)
{
	const __s64 nb = 1700000000LL;
	const __s64 na = 1700086400LL;
	struct cert cert = {};
	EVP_PKEY *pkey = NULL;
	size_t der_len = 0;
	__u8 *der = NULL;

	ASSERT_EQ(make_cert_der(nb, na, &pkey, &der, &der_len), 0);
	ASSERT_EQ(cert_read_der(der, der_len, &cert), 0);

	EXPECT_EQ(cert_valid_at(&cert, nb - 1), -EKEYEXPIRED);
	EXPECT_EQ(cert_valid_at(&cert, nb), 0);
	EXPECT_EQ(cert_valid_at(&cert, nb + 3600), 0);
	EXPECT_EQ(cert_valid_at(&cert, na), 0);
	EXPECT_EQ(cert_valid_at(&cert, na + 1), -EKEYEXPIRED);

	cert_free(&cert);
	EVP_PKEY_free(pkey);
	xfree(der, der_len);
}

static void vouch_v2_enforces_expiration_and_integrity(void)
{
	const __s64 nb = 1700000000LL;
	const __s64 na = 1800000000LL;
	const __s64 exp = 1700086400LL;
	char tmpl[] = "/tmp/shirudo-unit-keys-v2-XXXXXX";
	__u8 *der_a = NULL, *der_b = NULL;
	size_t len_a = 0, len_b = 0;
	__u8 *payload = NULL, *cms = NULL, *v2 = NULL;
	size_t payload_sz = 0, cms_sz = 0, v2_sz = 0;
	EVP_PKEY *pkey_a = NULL, *pkey_b = NULL;
	__u8 sha_a[32], fp_a[32], voucher[32];
	char cert_path[512];
	char *dir;

	dir = mkdtemp(tmpl);
	ASSERT_TRUE(dir);
	ASSERT_TRUE(strsprintf(cert_path, sizeof(cert_path), "%s/cert.der",
			       dir) > 0);
	ASSERT_EQ(make_cert_der(nb, na, &pkey_a, &der_a, &len_a), 0);
	ASSERT_EQ(make_cert_der(nb, na, &pkey_b, &der_b, &len_b), 0);
	ASSERT_EQ(keys_digest_der(der_a, len_a, sha_a, fp_a), 0);
	ASSERT_EQ(write_raw(cert_path, der_a, len_a), 0);
	ASSERT_EQ(keys_load(dir, NULL, false, &set), 0);
	ASSERT_EQ(set.n, 1u);

	ASSERT_EQ(keys_vouch_payload_v2(der_b, len_b, exp, &payload,
					&payload_sz), 0);
	ASSERT_EQ(sign_detached_cms(pkey_a, der_a, len_a, payload, payload_sz,
				    &cms, &cms_sz), 0);
	ASSERT_EQ(keys_vouch_encode_v2(exp, cms, cms_sz, &v2, &v2_sz), 0);

	/* Valid inside window and at exact boundary. */
	EXPECT_EQ(keys_verify_vouch_at(&set, der_b, len_b, v2, v2_sz,
				       exp - 10, voucher), 0);
	EXPECT_MEMEQ(voucher, fp_a, sizeof(fp_a));
	EXPECT_EQ(keys_verify_vouch_at(&set, der_b, len_b, v2, v2_sz,
				       exp, voucher), 0);

	/* Expired vouch at exp + 1 -> -EKEYEXPIRED. */
	EXPECT_EQ(keys_verify_vouch_at(&set, der_b, len_b, v2, v2_sz,
				       exp + 1, voucher), -EKEYEXPIRED);

	/* Signer certificate outside its own X.509 validity -> -EKEYEXPIRED. */
	EXPECT_EQ(keys_verify_vouch_at(&set, der_b, len_b, v2, v2_sz,
				       nb - 1, voucher), -EKEYEXPIRED);

	/* Extending the header's not_after breaks the signed payload. */
	put_be64(v2 + sizeof(KEYS_VOUCH_V2_PREFIX), (__u64)(exp + 3600));
	EXPECT_EQ(keys_verify_vouch_at(&set, der_b, len_b, v2, v2_sz,
				       exp + 10, voucher), -EKEYREJECTED);

	xfree(v2, v2_sz);
	xfree(cms, cms_sz);
	xfree(payload, payload_sz);
	EVP_PKEY_free(pkey_b);
	EVP_PKEY_free(pkey_a);
	xfree(der_b, len_b);
	xfree(der_a, len_a);
	rm_rf(dir);
}

static void an_image_keeps_what_a_revoked_voucher_admitted(void)
{
	const __s64 nb = 1700000000LL;
	const __s64 na = 2500000000LL;
	char tmpl[] = "/tmp/shirudo-unit-keys-u13-XXXXXX";
	__u8 *der_a = NULL, *der_b = NULL, *der_c = NULL;
	size_t len_a = 0, len_b = 0, len_c = 0;
	EVP_PKEY *pk_a = NULL, *pk_b = NULL, *pk_c = NULL;
	__u8 *pay_b = NULL, *sig_b = NULL, *pay_c = NULL, *sig_c = NULL;
	size_t pay_b_sz = 0, sig_b_sz = 0, pay_c_sz = 0, sig_c_sz = 0;
	__u8 sha[32], fp_a[32], fp_b[32], fp_c[32];
	char fp_b_hex[65], fp_c_hex[65];
	char path[512], primary[512];
	int root_fd = -1;
	char *dir;

	dir = mkdtemp(tmpl);
	ASSERT_TRUE(dir);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted", dir) > 0);
	ASSERT_EQ(mkdir(path, 0700), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/revoked", dir) > 0);
	ASSERT_EQ(mkdir(path, 0700), 0);

	ASSERT_EQ(make_cert_der(nb, na, &pk_a, &der_a, &len_a), 0);
	ASSERT_EQ(make_cert_der(nb, na, &pk_b, &der_b, &len_b), 0);
	ASSERT_EQ(make_cert_der(nb, na, &pk_c, &der_c, &len_c), 0);
	ASSERT_EQ(keys_digest_der(der_a, len_a, sha, fp_a), 0);
	ASSERT_EQ(keys_digest_der(der_b, len_b, sha, fp_b), 0);
	ASSERT_EQ(keys_digest_der(der_c, len_c, sha, fp_c), 0);
	hex_encode(fp_b, 32, fp_b_hex);
	hex_encode(fp_c, 32, fp_c_hex);

	/* Primary A vouches B; B vouches C. */
	ASSERT_TRUE(strsprintf(primary, sizeof(primary), "%s/cert.der",
			       dir) > 0);
	ASSERT_EQ(write_raw(primary, der_a, len_a), 0);

	ASSERT_EQ(keys_vouch_payload(der_b, len_b, &pay_b, &pay_b_sz), 0);
	ASSERT_EQ(sign_detached_cms(pk_a, der_a, len_a, pay_b, pay_b_sz,
				    &sig_b, &sig_b_sz), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.der",
			       dir, fp_b_hex) > 0);
	ASSERT_EQ(write_raw(path, der_b, len_b), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.vouch",
			       dir, fp_b_hex) > 0);
	ASSERT_EQ(write_raw(path, sig_b, sig_b_sz), 0);

	ASSERT_EQ(keys_vouch_payload(der_c, len_c, &pay_c, &pay_c_sz), 0);
	ASSERT_EQ(sign_detached_cms(pk_b, der_b, len_b, pay_c, pay_c_sz,
				    &sig_c, &sig_c_sz), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.der",
			       dir, fp_c_hex) > 0);
	ASSERT_EQ(write_raw(path, der_c, len_c), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.vouch",
			       dir, fp_c_hex) > 0);
	ASSERT_EQ(write_raw(path, sig_c, sig_c_sz), 0);

	/* Before revoking B, all three A, B, C are admitted. */
	root_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(root_fd >= 0);
	ASSERT_EQ(keys_load_image_at(primary, root_fd, true, &set), 0);
	EXPECT_EQ(set.n, 3u);
	EXPECT_EQ(set.n_revoked, 0u);
	EXPECT_EQ(set.n_unvouched, 0u);

	/*
	 * Revoke B. A directory of keys drops what B vouched for; a config
	 * image keeps it, which is what lets an operator revoke the signer
	 * that vouched for its successor (U13).
	 */
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/revoked/%s.der",
			       dir, fp_b_hex) > 0);
	ASSERT_EQ(write_raw(path, der_b, len_b), 0);

	ASSERT_EQ(keys_load(dir, NULL, true, &set), 0);
	EXPECT_EQ(set.n, 1u);
	EXPECT_EQ(set.n_revoked, 1u);
	EXPECT_EQ(set.n_unvouched, 1u);
	EXPECT_TRUE(keys_member(&set, fp_a));
	EXPECT_TRUE(!keys_member(&set, fp_b));
	EXPECT_TRUE(!keys_member(&set, fp_c));

	ASSERT_EQ(keys_load_image_at(primary, root_fd, true, &set), 0);
	EXPECT_EQ(set.n, 2u);
	EXPECT_EQ(set.n_revoked, 1u);
	EXPECT_EQ(set.n_unvouched, 0u);
	EXPECT_TRUE(keys_member(&set, fp_a));
	EXPECT_TRUE(!keys_member(&set, fp_b));
	EXPECT_TRUE(keys_member(&set, fp_c));

	close(root_fd);
	xfree(sig_c, sig_c_sz);
	xfree(pay_c, pay_c_sz);
	xfree(sig_b, sig_b_sz);
	xfree(pay_b, pay_b_sz);
	EVP_PKEY_free(pk_c);
	EVP_PKEY_free(pk_b);
	EVP_PKEY_free(pk_a);
	xfree(der_c, len_c);
	xfree(der_b, len_b);
	xfree(der_a, len_a);
	rm_rf(dir);
}

static void boot_admission_ignores_clock_and_staging_enforces_validity(void)
{
	char tmpl_exp[] = "/tmp/shirudo-unit-keys-exp-XXXXXX";
	char tmpl_adm[] = "/tmp/shirudo-unit-keys-adm-XXXXXX";
	__u8 *der_exp_signer = NULL, *der_a = NULL;
	__u8 *der_ok = NULL, *der_past = NULL, *der_fut = NULL;
	size_t len_exp_signer = 0, len_a = 0;
	size_t len_ok = 0, len_past = 0, len_fut = 0;
	EVP_PKEY *pk_exp_signer = NULL, *pk_a = NULL;
	EVP_PKEY *pk_ok = NULL, *pk_past = NULL, *pk_fut = NULL;
	__u8 *pay = NULL, *sig = NULL, *cms = NULL, *v2 = NULL;
	size_t pay_sz = 0, sig_sz = 0, cms_sz = 0, v2_sz = 0;
	__u8 sha[32], fp_a[32], fp_ok[32], fp_past[32], fp_fut[32], voucher[32];
	char fp_ok_hex[65], fp_past_hex[65], fp_fut_hex[65];
	char path[512], primary[512];
	char *dir_exp, *dir_adm;
	__s64 now = (__s64)time(NULL);
	int root_fd = -1;

	dir_exp = mkdtemp(tmpl_exp);
	dir_adm = mkdtemp(tmpl_adm);
	ASSERT_TRUE(dir_exp && dir_adm);

	ASSERT_EQ(make_cert_der(now - 7200, now - 3600, &pk_exp_signer,
				&der_exp_signer, &len_exp_signer), 0);
	ASSERT_EQ(make_cert_der(now - 3600, now + 86400, &pk_a, &der_a,
				&len_a), 0);
	ASSERT_EQ(make_cert_der(now - 3600, now + 86400, &pk_ok, &der_ok,
				&len_ok), 0);
	ASSERT_EQ(make_cert_der(now - 7200, now - 3600, &pk_past, &der_past,
				&len_past), 0);
	ASSERT_EQ(make_cert_der(now + 3600, now + 7200, &pk_fut, &der_fut,
				&len_fut), 0);

	/* Upstream v1 behaviour: v1 vouches do not check the voucher's clock. */
	ASSERT_TRUE(strsprintf(primary, sizeof(primary), "%s/cert.der",
			       dir_exp) > 0);
	ASSERT_EQ(write_raw(primary, der_exp_signer, len_exp_signer), 0);
	ASSERT_EQ(keys_load(dir_exp, NULL, false, &set), 0);
	ASSERT_EQ(keys_vouch_payload(der_ok, len_ok, &pay, &pay_sz), 0);
	ASSERT_EQ(sign_detached_cms(pk_exp_signer, der_exp_signer,
				    len_exp_signer, pay, pay_sz, &sig,
				    &sig_sz), 0);
	EXPECT_EQ(keys_verify_vouch(&set, der_ok, len_ok, sig, sig_sz,
				    voucher), 0);
	xfree(sig, sig_sz);
	xfree(pay, pay_sz);

	/* Boot-time admission admits valid signatures regardless of clock. */
	ASSERT_EQ(keys_digest_der(der_a, len_a, sha, fp_a), 0);
	ASSERT_EQ(keys_digest_der(der_ok, len_ok, sha, fp_ok), 0);
	ASSERT_EQ(keys_digest_der(der_past, len_past, sha, fp_past), 0);
	ASSERT_EQ(keys_digest_der(der_fut, len_fut, sha, fp_fut), 0);
	hex_encode(fp_ok, 32, fp_ok_hex);
	hex_encode(fp_past, 32, fp_past_hex);
	hex_encode(fp_fut, 32, fp_fut_hex);

	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted", dir_adm) > 0);
	ASSERT_EQ(mkdir(path, 0700), 0);
	ASSERT_TRUE(strsprintf(primary, sizeof(primary), "%s/cert.der",
			       dir_adm) > 0);
	ASSERT_EQ(write_raw(primary, der_a, len_a), 0);

	/* der_ok has an expired v2 vouch (not_after = now - 10). */
	ASSERT_EQ(keys_vouch_payload_v2(der_ok, len_ok, now - 10, &pay,
					&pay_sz), 0);
	ASSERT_EQ(sign_detached_cms(pk_a, der_a, len_a, pay, pay_sz, &cms,
				    &cms_sz), 0);
	ASSERT_EQ(keys_vouch_encode_v2(now - 10, cms, cms_sz, &v2, &v2_sz), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.der",
			       dir_adm, fp_ok_hex) > 0);
	ASSERT_EQ(write_raw(path, der_ok, len_ok), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.vouch",
			       dir_adm, fp_ok_hex) > 0);
	ASSERT_EQ(write_raw(path, v2, v2_sz), 0);
	xfree(v2, v2_sz);
	xfree(cms, cms_sz);
	xfree(pay, pay_sz);

	root_fd = open(dir_adm, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(root_fd >= 0);

	/* Boot admits der_ok despite expired v2 vouch; stage/update refuses it. */
	ASSERT_EQ(keys_load_image_at(primary, root_fd, true, &set), 0);
	EXPECT_EQ(set.n, 2u);
	EXPECT_EQ(set.n_unvouched, 0u);
	EXPECT_TRUE(keys_member(&set, fp_ok));
	EXPECT_EQ(keys_validate_image_validity_at(primary, root_fd, now),
		  -EKEYEXPIRED);
	EXPECT_EQ(keys_validate_image_validity_at(primary, root_fd, now - 20),
		  0);

	/* Add expired and not-yet-valid certs with v1 vouches. */
	ASSERT_EQ(keys_vouch_payload(der_past, len_past, &pay, &pay_sz), 0);
	ASSERT_EQ(sign_detached_cms(pk_a, der_a, len_a, pay, pay_sz, &sig,
				    &sig_sz), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.der",
			       dir_adm, fp_past_hex) > 0);
	ASSERT_EQ(write_raw(path, der_past, len_past), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.vouch",
			       dir_adm, fp_past_hex) > 0);
	ASSERT_EQ(write_raw(path, sig, sig_sz), 0);
	xfree(sig, sig_sz);
	xfree(pay, pay_sz);

	ASSERT_EQ(keys_vouch_payload(der_fut, len_fut, &pay, &pay_sz), 0);
	ASSERT_EQ(sign_detached_cms(pk_a, der_a, len_a, pay, pay_sz, &sig,
				    &sig_sz), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.der",
			       dir_adm, fp_fut_hex) > 0);
	ASSERT_EQ(write_raw(path, der_fut, len_fut), 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/trusted/%s.vouch",
			       dir_adm, fp_fut_hex) > 0);
	ASSERT_EQ(write_raw(path, sig, sig_sz), 0);
	xfree(sig, sig_sz);
	xfree(pay, pay_sz);

	/* Boot-time admission succeeds for all four regardless of clock. */
	ASSERT_EQ(keys_load(dir_adm, NULL, true, &set), 0);
	EXPECT_EQ(set.n, 4u);
	EXPECT_EQ(set.n_unvouched, 0u);
	ASSERT_EQ(keys_load_image_at(primary, root_fd, true, &set), 0);
	EXPECT_EQ(set.n, 4u);
	EXPECT_EQ(set.n_unvouched, 0u);

	/* Stage/update validity check refuses expired/future certs at now. */
	EXPECT_EQ(keys_validate_image_validity_at(primary, root_fd, now),
		  -EKEYEXPIRED);
	close(root_fd);

	EVP_PKEY_free(pk_fut);
	EVP_PKEY_free(pk_past);
	EVP_PKEY_free(pk_ok);
	EVP_PKEY_free(pk_a);
	EVP_PKEY_free(pk_exp_signer);
	xfree(der_fut, len_fut);
	xfree(der_past, len_past);
	xfree(der_ok, len_ok);
	xfree(der_a, len_a);
	xfree(der_exp_signer, len_exp_signer);
	rm_rf(dir_adm);
	rm_rf(dir_exp);
}

static const struct unit_case cases[] = {
	UNIT_CASE(member_is_found_by_fingerprint),
	UNIT_CASE(member_past_the_count_is_none),
	UNIT_CASE(cert_valid_at_enforces_validity_bounds),
	UNIT_CASE(vouch_v2_enforces_expiration_and_integrity),
	UNIT_CASE(an_image_keeps_what_a_revoked_voucher_admitted),
	UNIT_CASE(boot_admission_ignores_clock_and_staging_enforces_validity),
	{}
};

UNIT_SUITE(keys, cases);
