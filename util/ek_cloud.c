// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Cloud vTPM endorsement key public-key parsing and template matching
 * across AWS NitroTPM, GCP Shielded VM and Azure Trusted Launch vTPM.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <shirudo/byteorder.h>
#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "ek_cloud.h"
#include "malloc.h"

#define PEM_SPKI_HEADER		"-----BEGIN PUBLIC KEY-----"

static bool ascii_space(__u8 c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool b64_char(__u8 c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static bool p256_point_valid(const __u8 x[32], const __u8 y[32])
{
	EVP_PKEY_CTX *kctx = NULL, *vctx = NULL;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM params[3];
	__u8 point[65];
	bool ok = false;

	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);
	params[0] = OSSL_PARAM_construct_utf8_string("group", (char *)"P-256",
						     0);
	params[1] = OSSL_PARAM_construct_octet_string("pub", point,
						      sizeof(point));
	params[2] = OSSL_PARAM_construct_end();
	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (kctx && EVP_PKEY_fromdata_init(kctx) > 0 &&
	    EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0) {
		vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
		if (vctx && EVP_PKEY_public_check(vctx) == 1)
			ok = true;
	}
	EVP_PKEY_CTX_free(vctx);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(kctx);
	ERR_clear_error();
	return ok;
}

bool ek_cloud_template_valid(const struct tpm_public *pub)
{
	bool policy_l1, policy_l2;

	if (!pub)
		return false;
	if ((pub->attrs & TPM_EK_ATTRS) != TPM_EK_ATTRS ||
	    (pub->attrs & TPM_ATTR_SIGN_ENCRYPT) != 0 ||
	    (pub->attrs & ~(TPM_EK_ATTRS | TPM_ATTR_USER_WITH_AUTH)) != 0)
		return false;
	if (pub->sym_alg != TPM_ALG_AES || pub->sym_bits != 128 ||
	    pub->sym_mode != TPM_ALG_CFB || pub->scheme != TPM_ALG_NULL ||
	    pub->policy_len != 32)
		return false;
	policy_l1 = !memneq_explicit(pub->policy, shirudo_tpm_ek_policy, 32) &&
		    pub->attrs == TPM_EK_ATTRS;
	policy_l2 = !memneq_explicit(pub->policy, shirudo_tpm_ek_policy_l2, 32);
	if (!policy_l1 && !policy_l2)
		return false;
	if (pub->type == TPM_ALG_RSA)
		return pub->rsa_bits == 2048 && pub->n_len == 256 &&
		       (pub->n[0] & 0x80) != 0 &&
		       (pub->rsa_exponent == 0 || pub->rsa_exponent == 65537);
	if (pub->type == TPM_ALG_ECC)
		return pub->curve == TPM_ECC_NIST_P256 &&
		       p256_point_valid(pub->x, pub->y);
	return false;
}

static int extract_evp_pubkey(EVP_PKEY *pk, struct ek_cloud_key *out)
{
	BIGNUM *a = NULL, *b = NULL;
	EVP_PKEY_CTX *vctx = NULL;
	char group[32] = "";
	int id, ret = -EINVAL;

	id = EVP_PKEY_get_base_id(pk);
	if (id == EVP_PKEY_RSA) {
		if (!EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &a) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &b) ||
		    BN_is_negative(a) || BN_is_negative(b))
			goto out;
		if (BN_num_bytes(a) != 256 || BN_num_bytes(b) > 4) {
			ret = -EPROTONOSUPPORT;
			goto out;
		}
		out->n_len = (size_t)BN_bn2bin(a, out->n);
		out->e = (__u32)BN_get_word(b);
		if (out->n_len != 256 || !(out->n[0] & 0x80) ||
		    out->e != 65537) {
			ret = -EPROTONOSUPPORT;
			goto out;
		}
		out->rsa = true;
		ret = 0;
	} else if (id == EVP_PKEY_EC) {
		if (!EVP_PKEY_get_utf8_string_param(pk,
						    OSSL_PKEY_PARAM_GROUP_NAME,
						    group, sizeof(group),
						    NULL))
			goto out;
		if (strcmp(group, "P-256") && strcmp(group, "prime256v1")) {
			ret = -EPROTONOSUPPORT;
			goto out;
		}
		vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, NULL);
		if (!vctx || EVP_PKEY_public_check(vctx) != 1 ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &a) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &b) ||
		    BN_is_negative(a) || BN_is_negative(b) ||
		    BN_bn2binpad(a, out->x, 32) != 32 ||
		    BN_bn2binpad(b, out->y, 32) != 32)
			goto out;
		out->rsa = false;
		ret = 0;
	} else {
		ret = -EPROTONOSUPPORT;
	}
out:
	EVP_PKEY_CTX_free(vctx);
	BN_free(a);
	BN_free(b);
	ERR_clear_error();
	return ret;
}

static int parse_tpm2b(const __u8 *buf, size_t len, struct ek_cloud_key *out)
{
	size_t tpmt_len;
	int ret;

	ret = tpm_public_unmarshal(buf, len, &out->tpm_pub);
	if (ret)
		return ret;
	if (!ek_cloud_template_valid(&out->tpm_pub))
		return -EKEYREJECTED;
	tpmt_len = len - 2;
	if (tpmt_len > sizeof(out->tpmt))
		return -E2BIG;
	memcpy(out->tpmt, buf + 2, tpmt_len);
	out->tpmt_len = tpmt_len;
	ret = tpm_object_name(out->tpmt, out->tpmt_len, out->name);
	if (ret)
		return ret;
	out->format = EK_CLOUD_TPM2B;
	out->rsa = out->tpm_pub.type == TPM_ALG_RSA;
	if (out->rsa) {
		memcpy(out->n, out->tpm_pub.n, 256);
		out->n_len = 256;
		out->e = 65537;
	} else {
		memcpy(out->x, out->tpm_pub.x, 32);
		memcpy(out->y, out->tpm_pub.y, 32);
	}
	return 0;
}

static int parse_der_spki(const __u8 *buf, size_t len, struct ek_cloud_key *out)
{
	const __u8 *p = buf;
	EVP_PKEY *pk;
	int ret;

	if (!len || len > LONG_MAX)
		return -EINVAL;
	pk = d2i_PUBKEY(NULL, &p, (long)len);
	ERR_clear_error();
	if (!pk)
		return -EINVAL;
	if (p != buf + len) {
		EVP_PKEY_free(pk);
		return -EINVAL;
	}
	ret = extract_evp_pubkey(pk, out);
	EVP_PKEY_free(pk);
	if (!ret)
		out->format = EK_CLOUD_SPKI;
	return ret;
}

static int parse_pem_spki(const __u8 *buf, size_t len, struct ek_cloud_key *out)
{
	size_t off = 0, hdr_len = sizeof(PEM_SPKI_HEADER) - 1;
	EVP_PKEY *pk;
	char rem[64];
	BIO *bio;
	int n, ret;

	if (len > INT_MAX)
		return -EINVAL;
	while (off < len && ascii_space(buf[off]))
		off++;
	if (len - off < hdr_len ||
	    memcmp(buf + off, PEM_SPKI_HEADER, hdr_len))
		return -EINVAL;
	bio = BIO_new_mem_buf(buf + off, (int)(len - off));
	if (!bio)
		return -ENOMEM;
	pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	ERR_clear_error();
	if (!pk) {
		BIO_free(bio);
		return -EINVAL;
	}
	while ((n = BIO_read(bio, rem, sizeof(rem))) > 0) {
		int i;

		for (i = 0; i < n; i++) {
			if (!ascii_space((__u8)rem[i])) {
				EVP_PKEY_free(pk);
				BIO_free(bio);
				return -EINVAL;
			}
		}
	}
	BIO_free(bio);
	ret = extract_evp_pubkey(pk, out);
	EVP_PKEY_free(pk);
	if (!ret)
		out->format = EK_CLOUD_SPKI;
	return ret;
}

static int parse_base64_payload(const __u8 *buf, size_t len,
				struct ek_cloud_key *out)
{
	size_t clean_len = 0, raw_cap, raw_len = 0, i, pad = 0;
	__u8 *raw = NULL;
	char *clean;
	int ret;

	clean = xmalloc(len + 1);
	if (!clean)
		return -ENOMEM;
	for (i = 0; i < len; i++) {
		if (ascii_space(buf[i]))
			continue;
		if (!b64_char(buf[i])) {
			xfree(clean, len + 1);
			return -EINVAL;
		}
		if (buf[i] == '=') {
			pad++;
			if (pad > 2) {
				xfree(clean, len + 1);
				return -EINVAL;
			}
		} else if (pad) {
			xfree(clean, len + 1);
			return -EINVAL;
		}
		clean[clean_len++] = (char)buf[i];
	}
	clean[clean_len] = '\0';
	if (!clean_len || (clean_len % 4) != 0) {
		xfree(clean, len + 1);
		return -EINVAL;
	}
	raw_cap = 3 * (clean_len / 4);
	raw = xmalloc(raw_cap ? raw_cap : 1);
	if (!raw) {
		xfree(clean, len + 1);
		return -ENOMEM;
	}
	ret = base64_decode(clean, clean_len, raw, raw_cap, &raw_len);
	xfree(clean, len + 1);
	if (ret || !raw_len) {
		xfree(raw, raw_cap ? raw_cap : 1);
		return -EINVAL;
	}
	ret = parse_tpm2b(raw, raw_len, out);
	if (ret == -EINVAL)
		ret = parse_der_spki(raw, raw_len, out);
	xfree(raw, raw_cap ? raw_cap : 1);
	return ret;
}

int ek_cloud_parse(const void *data, size_t len, struct ek_cloud_key *out)
{
	const __u8 *bytes = data;
	size_t off = 0;
	int ret;

	if (!data || !out || !len || len > EK_CLOUD_MAX)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	while (off < len && ascii_space(bytes[off]))
		off++;
	if (off < len && len - off >= sizeof("-----BEGIN ") - 1 &&
	    !memcmp(bytes + off, "-----BEGIN ", sizeof("-----BEGIN ") - 1))
		return parse_pem_spki(bytes, len, out);
	ret = parse_tpm2b(bytes, len, out);
	if (ret != -EINVAL)
		return ret;
	memset(out, 0, sizeof(*out));
	if (bytes[0] == 0x30)
		return parse_der_spki(bytes, len, out);
	return parse_base64_payload(bytes, len, out);
}

int ek_cloud_build_public(const struct ek_cloud_key *key,
			  enum ek_template tmpl,
			  struct tpm_public *pub,
			  __u8 tpmt[TPM_PUBLIC_MAX],
			  size_t *tpmt_len,
			  __u8 name[TPM_NAME_MAX])
{
	int ret;

	if (!key || !pub || !tpmt || !tpmt_len || !name)
		return -EINVAL;
	memset(pub, 0, sizeof(*pub));
	pub->type = key->rsa ? TPM_ALG_RSA : TPM_ALG_ECC;
	if (tmpl == EK_TEMPLATE_L1) {
		pub->attrs = TPM_EK_ATTRS;
		memcpy(pub->policy, shirudo_tpm_ek_policy, 32);
	} else if (tmpl == EK_TEMPLATE_L2) {
		pub->attrs = TPM_EK_ATTRS | TPM_ATTR_USER_WITH_AUTH;
		memcpy(pub->policy, shirudo_tpm_ek_policy_l2, 32);
	} else {
		return -EINVAL;
	}
	pub->policy_len = 32;
	pub->sym_alg = TPM_ALG_AES;
	pub->sym_bits = 128;
	pub->sym_mode = TPM_ALG_CFB;
	pub->scheme = TPM_ALG_NULL;
	if (key->rsa) {
		if (key->n_len != 256 || !(key->n[0] & 0x80) ||
		    key->e != 65537)
			return -EINVAL;
		pub->rsa_bits = 2048;
		pub->rsa_exponent = 0;
		pub->n_len = 256;
		memcpy(pub->n, key->n, 256);
	} else {
		if (!p256_point_valid(key->x, key->y))
			return -EINVAL;
		pub->curve = TPM_ECC_NIST_P256;
		memcpy(pub->x, key->x, 32);
		memcpy(pub->y, key->y, 32);
	}
	ret = tpm_public_marshal(pub, tpmt, TPM_PUBLIC_MAX, tpmt_len);
	if (ret)
		return ret;
	return tpm_object_name(tpmt, *tpmt_len, name);
}

int ek_cloud_name(const void *cloud_pub, size_t cloud_len,
		  enum ek_template tmpl, bool force_template,
		  bool *out_rsa, enum ek_template *out_tmpl,
		  __u8 out_ek_name[TPM_NAME_MAX])
{
	__u8 tpmt[TPM_PUBLIC_MAX];
	struct ek_cloud_key key;
	struct tpm_public pub;
	size_t tpmt_len;
	int ret;

	if (!out_ek_name)
		return -EINVAL;
	ret = ek_cloud_parse(cloud_pub, cloud_len, &key);
	if (ret)
		return ret;
	if (out_rsa)
		*out_rsa = key.rsa;
	if (key.format == EK_CLOUD_TPM2B && !force_template) {
		if (out_tmpl)
			*out_tmpl = !memneq_explicit(key.tpm_pub.policy,
						     shirudo_tpm_ek_policy, 32) ?
				    EK_TEMPLATE_L1 : EK_TEMPLATE_L2;
		memcpy(out_ek_name, key.name, TPM_NAME_LEN);
		return 0;
	}
	if (out_tmpl)
		*out_tmpl = tmpl;
	return ek_cloud_build_public(&key, tmpl, &pub, tpmt, &tpmt_len,
				     out_ek_name);
}

int ek_cloud_verify_presented(const void *cloud_pub, size_t cloud_len,
			      const void *presented_tpm2b,
			      size_t presented_len,
			      __u8 out_ek_name[TPM_NAME_MAX],
			      size_t *out_ek_name_len)
{
	const __u8 *p_bytes = presented_tpm2b, *tpmt;
	struct ek_cloud_key ck;
	struct tpm_public pres;
	size_t tpmt_len;
	int ret;

	if (!presented_tpm2b || !presented_len || !out_ek_name ||
	    !out_ek_name_len)
		return -EINVAL;
	*out_ek_name_len = 0;
	memset(out_ek_name, 0, TPM_NAME_MAX);
	ret = ek_cloud_parse(cloud_pub, cloud_len, &ck);
	if (ret)
		return ret;
	if (presented_len >= 2 && get_be16(p_bytes) == presented_len - 2) {
		ret = tpm_public_unmarshal(p_bytes, presented_len, &pres);
		tpmt = p_bytes + 2;
		tpmt_len = presented_len - 2;
	} else {
		ret = tpm_public_parse(p_bytes, presented_len, &pres);
		tpmt = p_bytes;
		tpmt_len = presented_len;
	}
	if (ret) {
		memset(out_ek_name, 0, TPM_NAME_MAX);
		return ret;
	}
	if (!ek_cloud_template_valid(&pres))
		return -EKEYREJECTED;
	if (ck.format == EK_CLOUD_TPM2B) {
		if (tpmt_len != ck.tpmt_len ||
		    memneq_explicit(tpmt, ck.tpmt, tpmt_len))
			return -EKEYREJECTED;
	} else {
		bool pres_rsa = pres.type == TPM_ALG_RSA;

		if (pres_rsa != ck.rsa)
			return -EKEYREJECTED;
		if (ck.rsa) {
			__u32 exp = pres.rsa_exponent ? pres.rsa_exponent :
				    65537;

			if (pres.n_len != 256 || exp != 65537 ||
			    memneq_explicit(pres.n, ck.n, 256))
				return -EKEYREJECTED;
		} else {
			if (memneq_explicit(pres.x, ck.x, 32) ||
			    memneq_explicit(pres.y, ck.y, 32))
				return -EKEYREJECTED;
		}
	}
	ret = tpm_object_name(tpmt, tpmt_len, out_ek_name);
	if (ret)
		return ret;
	*out_ek_name_len = TPM_NAME_LEN;
	return 0;
}
