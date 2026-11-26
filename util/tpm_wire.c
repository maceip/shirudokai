// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * TPM 2.0 wire-format helpers shared by the target and the verifier.
 */

#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "tpm_wire.h"

#define TPM_CC_POLICY_OR		0x00000171u
#define TPM_CC_POLICY_COMMAND_CODE	0x0000016Cu
#define TPM_CC_POLICY_SIGNED		0x00000160u
#define TPM_CC_POLICY_PCR		0x0000017Fu
#define TPM_CC_POLICY_NV_WRITTEN	0x0000018Fu

struct reader {
	const __u8	*p;
	size_t		left;
};

static int get8(struct reader *r, __u8 *v)
{
	if (r->left < 1)
		return -EINVAL;
	*v = r->p[0];
	r->p++;
	r->left--;
	return 0;
}

static int get16(struct reader *r, __u16 *v)
{
	if (r->left < 2)
		return -EINVAL;
	*v = get_be16(r->p);
	r->p += 2;
	r->left -= 2;
	return 0;
}

static int get32(struct reader *r, __u32 *v)
{
	if (r->left < 4)
		return -EINVAL;
	*v = get_be32(r->p);
	r->p += 4;
	r->left -= 4;
	return 0;
}

static int get64(struct reader *r, __u64 *v)
{
	__u32 hi, lo;

	if (get32(r, &hi) || get32(r, &lo))
		return -EINVAL;
	*v = ((__u64)hi << 32) | lo;
	return 0;
}

static int get2b(struct reader *r, const __u8 **data, size_t *len,
		 size_t max)
{
	__u16 n;

	if (get16(r, &n) || n > r->left || n > max)
		return -EINVAL;
	*data = r->p;
	*len = n;
	r->p += n;
	r->left -= n;
	return 0;
}

static int get2b_fixed(struct reader *r, __u8 *out, size_t want)
{
	const __u8 *d;
	size_t n;

	if (get2b(r, &d, &n, want) || n != want)
		return -EINVAL;
	memcpy(out, d, n);
	return 0;
}

static int policy_hash(const __u8 prev[32], __u32 cc,
		       const __u8 *a, size_t a_len,
		       const __u8 *b, size_t b_len, __u8 out[32])
{
	struct sha256_ctx ctx;
	__u8 cc_be[4];

	/* prev and out may be one buffer; out changes only once done. */
	put_be32(cc_be, cc);
	if (sha256_init(&ctx) != 0) {
		memset(out, 0, 32);
		return -EIO;
	}
	if (sha256_update(&ctx, prev, 32) != 0 ||
	    sha256_update(&ctx, cc_be, sizeof(cc_be)) != 0 ||
	    (a_len && sha256_update(&ctx, a, a_len) != 0) ||
	    (b_len && sha256_update(&ctx, b, b_len) != 0) ||
	    sha256_final(&ctx, out) != 0) {
		memset(out, 0, 32);
		sha256_free(&ctx);
		return -EIO;
	}
	return 0;
}

int tpm_policy_nv_written(const __u8 prev[32], bool written,
			  __u8 out[32])
{
	__u8 set = written ? 1 : 0;

	return policy_hash(prev, TPM_CC_POLICY_NV_WRITTEN, &set, 1, NULL, 0,
			   out);
}

static void
tpm_pcr_selection(__u32 pcr_mask,
		  __u8 out[TPM_PCR_SELECTION_LEN])
{
	put_be32(out, 1);
	put_be16(out + 4, TPM_ALG_SHA256);
	out[6] = TPM_PCR_SELECT_LEN;
	out[7] = (__u8)(pcr_mask & 0xff);
	out[8] = (__u8)(pcr_mask >> 8 & 0xff);
	out[9] = (__u8)(pcr_mask >> 16 & 0xff);
}

int tpm_policy_pcr(const __u8 prev[32], __u32 pcr_mask,
		   const __u8 pcr_digest[32], __u8 out[32])
{
	__u8 sel[TPM_PCR_SELECTION_LEN];

	tpm_pcr_selection(pcr_mask, sel);
	return policy_hash(prev, TPM_CC_POLICY_PCR, sel, sizeof(sel),
			   pcr_digest, 32, out);
}

int tpm_policy_or(const __u8 a[32], const __u8 b[32], __u8 out[32])
{
	static const __u8 zero[32];

	return policy_hash(zero, TPM_CC_POLICY_OR, a, 32, b, 32, out);
}

/*
 * The primary's fixed TPMT_PUBLIC adds a 24-byte prefix to the modulus.
 * It excludes the outer TPM2B_PUBLIC size field.
 */
void tpm_writer_public(const __u8 modulus[TPM_NV_RSA_BYTES],
		       __u8 out[TPM_NV_RSA_PUBLIC_AREA_LEN])
{
	put_be16(out, TPM_ALG_RSA);	/* type */
	put_be16(out + 2, TPM_ALG_SHA256);	/* nameAlg */
	put_be32(out + 4, TPM_WRITER_ATTRS);
	put_be16(out + 8, 0);		/* Empty authPolicy: size only. */
	put_be16(out + 10, TPM_ALG_NULL);	/* symmetric.algorithm */
	put_be16(out + 12, TPM_ALG_RSASSA);	/* scheme.scheme */
	put_be16(out + 14, TPM_ALG_SHA256);	/* scheme hash */
	put_be16(out + 16, 3072);		/* RSA keyBits */
	put_be32(out + 18, 65537);	/* RSA exponent F4: 2^16 + 1. */
	/* unique.rsa: two-byte size at offset 22, public-key bytes at offset 24. */
	tpm_put2b(out + 22, modulus, TPM_NV_RSA_BYTES);
}

int tpm_nv_extend_cphash(const __u8 name[TPM_NAME_LEN],
			 const __u8 event[32], __u8 out[32])
{
	__u8 command[4 + 2 * TPM_NAME_LEN + 2 + 32];

	put_be32(command, TPM_CC_NV_EXTEND);
	memcpy(command + 4, name, TPM_NAME_LEN);
	memcpy(command + 4 + TPM_NAME_LEN, name, TPM_NAME_LEN);
	tpm_put2b(command + 4 + 2 * TPM_NAME_LEN, event, 32);
	return sha256_buffer(command, sizeof(command), out);
}

int tpm_writer_auth_hash(const __u8 *nonce, size_t nonce_len,
			 const __u8 cphash[32], __u8 out[32])
{
	__u8 bytes[64 + 4 + 32 + sizeof(TPM_NV_POLICY_REF) - 1];

	if (!nonce_len || nonce_len > 64)
		return -EINVAL;
	memcpy(bytes, nonce, nonce_len);
	put_be32(bytes + nonce_len, 0);
	memcpy(bytes + nonce_len + 4, cphash, 32);
	memcpy(bytes + nonce_len + 4 + 32, TPM_NV_POLICY_REF,
	       sizeof(TPM_NV_POLICY_REF) - 1);
	return sha256_buffer(bytes, nonce_len + 4 + 32 + sizeof(TPM_NV_POLICY_REF) - 1,
			     out);
}

int tpm_policy_signed(const __u8 prev[32],
		      const __u8 writer_public[TPM_NV_RSA_BYTES],
		      __u8 out[32])
{
	__u8 public[TPM_NV_RSA_PUBLIC_AREA_LEN];
	__u8 bytes[32 + sizeof(TPM_NV_POLICY_REF) - 1];
	__u8 name[TPM_NAME_LEN];
	int ret;

	tpm_writer_public(writer_public, public);
	ret = tpm_object_name(public, sizeof(public), name);
	if (ret)
		return ret;
	ret = policy_hash(prev, TPM_CC_POLICY_SIGNED, name, sizeof(name), NULL,
			  0, out);
	if (ret)
		return ret;
	memcpy(bytes, out, 32);
	memcpy(bytes + 32, TPM_NV_POLICY_REF,
	       sizeof(TPM_NV_POLICY_REF) - 1);
	return sha256_buffer(bytes, sizeof(bytes), out);
}

int tpm_policy_command_code(const __u8 prev[32],
			    __u32 command_code, __u8 out[32])
{
	__u8 cc_be[4];

	put_be32(cc_be, command_code);
	return policy_hash(prev, TPM_CC_POLICY_COMMAND_CODE, cc_be,
			   sizeof(cc_be), NULL, 0, out);
}

int tpm_register_policy_final(const __u8 branch_written[32],
			      const __u8 branch_init[32],
			      const __u8 writer_public[TPM_NV_RSA_BYTES],
			      __u8 policy[32])
{
	int ret;

	ret = tpm_policy_or(branch_written, branch_init, policy);
	if (!ret)
		ret = tpm_policy_signed(policy, writer_public, policy);
	if (!ret)
		ret = tpm_policy_command_code(policy, TPM_CC_NV_EXTEND,
					      policy);
	return ret;
}

int tpm_register_policy(__u32 pcr_mask,
			const __u8 *pcr_values, size_t n_values,
			const __u8 writer_public[TPM_NV_RSA_BYTES],
			__u8 branch_written[32],
			__u8 branch_init[32], __u8 policy[32])
{
	static const __u8 zero[32];
	__u8 pcr_digest[32], unwritten[32];
	int ret;

	ret = tpm_policy_nv_written(zero, true, branch_written);
	if (!ret)
		ret = tpm_policy_nv_written(zero, false, unwritten);
	if (!ret)
		ret = sha256_buffer(pcr_values, 32 * n_values, pcr_digest);
	if (!ret)
		ret = tpm_policy_pcr(unwritten, pcr_mask, pcr_digest,
				     branch_init);
	if (ret)
		return ret;
	return tpm_register_policy_final(branch_written, branch_init,
					 writer_public, policy);
}

int tpm_nv_name(__u32 index, __u32 attrs,
		const __u8 policy[32], __u16 data_size,
		__u8 name[TPM_NAME_LEN])
{
	__u8 pub[4 + 2 + 4 + 2 + 32 + 2];

	put_be32(pub, index);
	put_be16(pub + 4, TPM_ALG_SHA256);
	put_be32(pub + 6, attrs);
	put_be16(pub + 10, 32);
	memcpy(pub + 12, policy, 32);
	put_be16(pub + 44, data_size);
	put_be16(name, TPM_ALG_SHA256);
	return sha256_buffer(pub, sizeof(pub), name + 2);
}

int tpm_object_name(const __u8 *public, size_t len,
		    __u8 name[TPM_NAME_LEN])
{
	struct reader r = { public, len };
	__u16 type, alg;

	if (get16(&r, &type) || get16(&r, &alg) ||
	    alg != TPM_ALG_SHA256)
		return -EINVAL;
	put_be16(name, TPM_ALG_SHA256);
	return sha256_buffer(public, len, name + 2);
}

int tpm_qualified_name(__u32 hierarchy,
		       const __u8 name[TPM_NAME_LEN],
		       __u8 out[TPM_NAME_LEN])
{
	__u8 buf[4 + TPM_NAME_LEN];

	put_be32(buf, hierarchy);
	memcpy(buf + 4, name, TPM_NAME_LEN);
	put_be16(out, TPM_ALG_SHA256);
	return sha256_buffer(buf, sizeof(buf), out + 2);
}

const __u8 shirudo_tpm_ek_policy[32] = {
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
	0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
	0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
};

const __u8 shirudo_tpm_ek_policy_l2[32] = {
	0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82,
	0xbc, 0xf5, 0xfd, 0x3a, 0x1a, 0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3,
	0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0x9b, 0xd4, 0x16, 0xca, 0x11,
};

int tpm_public_parse(const __u8 *buf, size_t len,
		     struct tpm_public *out)
{
	struct reader r = { buf, len };
	const __u8 *policy, *n;
	__u16 name_alg, kdf;

	memset(out, 0, sizeof(*out));
	if (get16(&r, &out->type) || get16(&r, &name_alg) ||
	    name_alg != TPM_ALG_SHA256 || get32(&r, &out->attrs) ||
	    get2b(&r, &policy, &out->policy_len, 32) ||
	    (out->policy_len && out->policy_len != 32))
		return -EINVAL;
	memcpy(out->policy, policy, out->policy_len);
	if (get16(&r, &out->sym_alg))
		return -EINVAL;
	if (out->sym_alg != TPM_ALG_NULL &&
	    (get16(&r, &out->sym_bits) || get16(&r, &out->sym_mode)))
		return -EINVAL;
	if (get16(&r, &out->scheme))
		return -EINVAL;
	if (out->scheme != TPM_ALG_NULL && get16(&r, &out->scheme_hash))
		return -EINVAL;
	if (out->type == TPM_ALG_ECC) {
		if (get16(&r, &out->curve) || get16(&r, &kdf) ||
		    kdf != TPM_ALG_NULL ||
		    get2b_fixed(&r, out->x, 32) || get2b_fixed(&r, out->y, 32))
			return -EINVAL;
	} else if (out->type == TPM_ALG_RSA) {
		if (get16(&r, &out->rsa_bits) || get32(&r, &out->rsa_exponent) ||
		    get2b(&r, &n, &out->n_len, sizeof(out->n)))
			return -EINVAL;
		memcpy(out->n, n, out->n_len);
	} else {
		return -EPROTONOSUPPORT;
	}
	if (r.left != 0)
		return -EINVAL;
	if ((out->sym_alg != TPM_ALG_NULL &&
	     (out->sym_alg != TPM_ALG_AES || out->sym_bits != 128 ||
	      out->sym_mode != TPM_ALG_CFB)) ||
	    (out->scheme != TPM_ALG_NULL &&
	     (out->scheme != TPM_ALG_ECDSA ||
	      out->scheme_hash != TPM_ALG_SHA256)) ||
	    (out->type == TPM_ALG_ECC &&
	     out->curve != TPM_ECC_NIST_P256) ||
	    (out->type == TPM_ALG_RSA &&
	     (out->rsa_bits != 2048 || out->n_len != 256 ||
	      (out->rsa_exponent && out->rsa_exponent != 65537))))
		return -EPROTONOSUPPORT;
	return 0;
}

int tpm_public_unmarshal(const __u8 *buf, size_t len,
			 struct tpm_public *out)
{
	if (!buf || !out || len < 2)
		return -EINVAL;
	if (get_be16(buf) != len - 2)
		return -EINVAL;
	return tpm_public_parse(buf + 2, len - 2, out);
}

int tpm_public_marshal(const struct tpm_public *pub,
		       __u8 *out, size_t cap, size_t *len)
{
	size_t need = 2 + 2 + 4 + 2 + pub->policy_len + 2 + 2, off = 0;

	if (pub->policy_len != 0 && pub->policy_len != 32)
		return -EINVAL;
	if (pub->sym_alg != TPM_ALG_NULL)
		need += 4;
	if (pub->scheme != TPM_ALG_NULL)
		need += 2;
	if (pub->type == TPM_ALG_ECC)
		need += 2 + 2 + 2 + 32 + 2 + 32;
	else if (pub->type == TPM_ALG_RSA && pub->n_len <= sizeof(pub->n))
		need += 2 + 4 + 2 + pub->n_len;
	else
		return -EINVAL;
	if (cap < need)
		return -E2BIG;
	put_be16(out + off, pub->type);
	off += 2;
	put_be16(out + off, TPM_ALG_SHA256);
	off += 2;
	put_be32(out + off, pub->attrs);
	off += 4;
	off += tpm_put2b(out + off, pub->policy, pub->policy_len);
	put_be16(out + off, pub->sym_alg);
	off += 2;
	if (pub->sym_alg != TPM_ALG_NULL) {
		put_be16(out + off, pub->sym_bits);
		put_be16(out + off + 2, pub->sym_mode);
		off += 4;
	}
	put_be16(out + off, pub->scheme);
	off += 2;
	if (pub->scheme != TPM_ALG_NULL) {
		put_be16(out + off, pub->scheme_hash);
		off += 2;
	}
	if (pub->type == TPM_ALG_ECC) {
		put_be16(out + off, pub->curve);
		put_be16(out + off + 2, TPM_ALG_NULL);
		off += 4;
		off += tpm_put2b(out + off, pub->x, 32);
		off += tpm_put2b(out + off, pub->y, 32);
	} else {
		put_be16(out + off, pub->rsa_bits);
		put_be32(out + off + 2, pub->rsa_exponent);
		off += 6;
		off += tpm_put2b(out + off, pub->n, pub->n_len);
	}
	*len = off;
	return 0;
}

int tpm_ecc_public_parse(const __u8 *buf, size_t len,
			 struct tpm_ecc_public *out)
{
	struct tpm_public pub;
	int ret;

	memset(out, 0, sizeof(*out));
	ret = tpm_public_parse(buf, len, &pub);
	if (ret)
		return ret;
	if (pub.type != TPM_ALG_ECC ||
	    pub.sym_alg != TPM_ALG_NULL ||
	    pub.scheme != TPM_ALG_ECDSA)
		return -EPROTONOSUPPORT;
	out->attrs = pub.attrs;
	out->scheme = pub.scheme;
	out->hash = pub.scheme_hash;
	out->curve = pub.curve;
	memcpy(out->x, pub.x, 32);
	memcpy(out->y, pub.y, 32);
	return 0;
}

int tpm_kdfa(const __u8 *key, size_t key_len, const char *label,
	     const __u8 *ctx_u, size_t u_len,
	     const __u8 *ctx_v, size_t v_len,
	     __u8 *out, size_t out_len)
{
	__u8 buf[4 + 64 + 1 + 2 * TPM_NAME_LEN + 4], block[32];
	size_t label_len = strlen(label), done = 0, off, n;
	int ret = 0;
	__u32 i;

	if (label_len > 64 || u_len > TPM_NAME_LEN ||
	    v_len > TPM_NAME_LEN || out_len > 4096)
		return -EINVAL;
	for (i = 1; done < out_len; i++) {
		put_be32(buf, i);
		off = 4;
		memcpy(buf + off, label, label_len);
		off += label_len;
		buf[off++] = 0;
		if (u_len)
			memcpy(buf + off, ctx_u, u_len);
		off += u_len;
		if (v_len)
			memcpy(buf + off, ctx_v, v_len);
		off += v_len;
		put_be32(buf + off, (__u32)(out_len * 8));
		off += 4;
		if (hmac_sha256(key, key_len, buf, off, block)) {
			ret = -EIO;
			break;
		}
		n = min(out_len - done, 32U);
		memcpy(out + done, block, n);
		done += n;
	}
	memzero_explicit(block, sizeof(block));
	return ret;
}

int tpm_kdfe(const __u8 z[32], const char *label,
	     const __u8 *party_u, size_t u_len,
	     const __u8 *party_v, size_t v_len, __u8 out[32])
{
	__u8 buf[4 + 32 + 64 + 1 + 2 * 64];
	size_t label_len = strlen(label), off = 4;
	int ret;

	if (label_len > 64 || u_len > 64 || v_len > 64)
		return -EINVAL;
	put_be32(buf, 1);
	memcpy(buf + off, z, 32);
	off += 32;
	memcpy(buf + off, label, label_len);
	off += label_len;
	buf[off++] = 0;
	if (u_len)
		memcpy(buf + off, party_u, u_len);
	off += u_len;
	if (v_len)
		memcpy(buf + off, party_v, v_len);
	off += v_len;
	ret = sha256_buffer(buf, off, out);
	memzero_explicit(buf, sizeof(buf));
	return ret;
}

int tpm_credential_protect(const __u8 seed[32],
			   const __u8 name[TPM_NAME_LEN],
			   const __u8 credential[TPM_CREDENTIAL_LEN],
			   __u8 out[TPM_ID_OBJECT_LEN])
{
	__u8 plain[2 + TPM_CREDENTIAL_LEN], enc[sizeof(plain)];
	__u8 mac_in[sizeof(enc) + TPM_NAME_LEN], mac[32];
	__u8 sym_key[16], hmac_key[32];
	int ret = -EIO;

	if (tpm_kdfa(seed, 32, "STORAGE", name, TPM_NAME_LEN,
		     NULL, 0, sym_key, sizeof(sym_key)))
		goto out;
	put_be16(plain, TPM_CREDENTIAL_LEN);
	memcpy(plain + 2, credential, TPM_CREDENTIAL_LEN);
	if (aes128_cfb_encrypt(sym_key, plain, sizeof(plain), enc) ||
	    tpm_kdfa(seed, 32, "INTEGRITY", NULL, 0, NULL, 0, hmac_key,
		     sizeof(hmac_key)))
		goto out;
	memcpy(mac_in, enc, sizeof(enc));
	memcpy(mac_in + sizeof(enc), name, TPM_NAME_LEN);
	if (hmac_sha256(hmac_key, sizeof(hmac_key), mac_in,
			sizeof(mac_in), mac))
		goto out;
	put_be16(out, 32);
	memcpy(out + 2, mac, 32);
	memcpy(out + 34, enc, sizeof(enc));
	ret = 0;
out:
	memzero_explicit(plain, sizeof(plain));
	memzero_explicit(sym_key, sizeof(sym_key));
	memzero_explicit(hmac_key, sizeof(hmac_key));
	return ret;
}

int tpm_ecdsa_signature_parse(const __u8 *buf, size_t len,
			      __u8 r_out[32], __u8 s_out[32])
{
	struct reader r = { buf, len };
	__u16 alg, hash;

	if (get16(&r, &alg) || alg != TPM_ALG_ECDSA ||
	    get16(&r, &hash) || hash != TPM_ALG_SHA256 ||
	    get2b_fixed(&r, r_out, 32) || get2b_fixed(&r, s_out, 32) ||
	    r.left != 0)
		return -EINVAL;
	return 0;
}

static int get_name(struct reader *r, __u8 *name, size_t *name_len)
{
	const __u8 *d;
	size_t n;

	if (get2b(r, &d, &n, TPM_NAME_LEN))
		return -EINVAL;
	memcpy(name, d, n);
	*name_len = n;
	return 0;
}

int tpm_attest_parse(const __u8 *buf, size_t len,
		     struct tpm_attest *out)
{
	struct reader r = { buf, len };
	__u32 magic;
	__u8 safe;

	memset(out, 0, sizeof(*out));
	if (get32(&r, &magic) || magic != TPM_GENERATED ||
	    get16(&r, &out->type) ||
	    get_name(&r, out->signer, &out->signer_len) ||
	    get2b(&r, &out->extra, &out->extra_len, 64) ||
	    get64(&r, &out->clock) || get32(&r, &out->reset_count) ||
	    get32(&r, &out->restart_count) || get8(&r, &safe) ||
	    get64(&r, &out->firmware_version))
		return -EINVAL;
	out->safe = safe != 0;

	if (out->type == TPM_ST_ATTEST_QUOTE) {
		__u32 count;
		__u16 alg;
		__u8 n;

		if (get32(&r, &count) || count != 1 || get16(&r, &alg) ||
		    alg != TPM_ALG_SHA256 || get8(&r, &n) ||
		    n != TPM_PCR_SELECT_LEN || r.left < n)
			return -EINVAL;
		out->pcr_mask = (__u32)r.p[0] | ((__u32)r.p[1] << 8) |
				((__u32)r.p[2] << 16);
		r.p += n;
		r.left -= n;
		if (get2b_fixed(&r, out->pcr_digest, 32) || r.left != 0)
			return -EINVAL;
		return 0;
	}
	if (out->type == TPM_ST_ATTEST_NV) {
		if (get_name(&r, out->index_name, &out->index_name_len) ||
		    get16(&r, &out->offset) ||
		    get2b(&r, &out->nv_data, &out->nv_len, 2048) ||
		    r.left != 0)
			return -EINVAL;
		return 0;
	}
	return -EPROTONOSUPPORT;
}

int tpm_attest_signer(const struct tpm_attest *a,
		      const __u8 ak_name[TPM_NAME_LEN], bool *is)
{
	__u8 qualified[TPM_NAME_LEN];
	int ret;

	ret = tpm_qualified_name(TPM_RH_ENDORSEMENT, ak_name, qualified);
	if (ret)
		return ret;
	*is = a->signer_len == TPM_NAME_LEN &&
	      !memneq_explicit(a->signer, qualified, TPM_NAME_LEN);
	return 0;
}

int tpm_attest_verify(const __u8 *attest, size_t len,
		      const __u8 *sig, size_t sig_len,
		      const __u8 x[32], const __u8 y[32])
{
	__u8 digest[CRYPTO_SHA256_LEN], r[32], s[32];
	int ret;

	if (tpm_ecdsa_signature_parse(sig, sig_len, r, s))
		return -EBADMSG;
	ret = sha256_buffer(attest, len, digest);
	if (!ret)
		ret = ecdsa_p256_verify(x, y, digest, r, s);
	return ret == -EINVAL ? -EKEYREJECTED : ret;
}

static bool otel_boot_id_valid(const char *boot_id, size_t *len_out)
{
	size_t i;

	if (!boot_id || !boot_id[0])
		return false;
	for (i = 0; i <= OTEL_BOOT_ID_MAX; i++) {
		__u8 c = (__u8)boot_id[i];

		if (!c) {
			*len_out = i;
			return true;
		}
		if (c <= 0x20 || c >= 0x7f)
			return false;
	}
	return false;
}

int otel_origin_digest(const char *boot_id, __u64 seq,
		       const __u8 body_sha256[32], __u8 out[32])
{
	__u8 digest[CRYPTO_SHA256_LEN], seq_be[8];
	struct sha256_ctx ctx;
	size_t boot_len;
	int ret;

	if (!body_sha256 || !out || !otel_boot_id_valid(boot_id, &boot_len))
		return -EINVAL;
	put_be32(seq_be, (__u32)(seq >> 32));
	put_be32(seq_be + 4, (__u32)seq);
	ret = sha256_init(&ctx);
	if (ret)
		return ret;
	ret = sha256_update(&ctx, OTEL_ORIGIN_PREFIX,
			    sizeof(OTEL_ORIGIN_PREFIX));
	if (!ret)
		ret = sha256_update(&ctx, seq_be, sizeof(seq_be));
	if (!ret)
		ret = sha256_update(&ctx, body_sha256, 32);
	if (!ret)
		ret = sha256_update(&ctx, boot_id, boot_len);
	if (!ret)
		ret = sha256_final(&ctx, digest);
	sha256_free(&ctx);
	if (!ret)
		memcpy(out, digest, sizeof(digest));
	return ret;
}
