// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What util/tpm_wire.c hands SHA-256, modelled as any result, for every
 * length a caller can pass: the policy digests, PolicyPCR's for every mask
 * and the register's for every count of PCR values, the object, NV and
 * qualified names, cpHash, the writer's authorization hash and the OTLP
 * origin digest only hash whole inputs into whole outputs, with a nonce or
 * printable boot ID of 1 to 64 bytes.
 */

#include "proof.h"
#include "../../../util/tpm_wire.c"

static int any_result(void)
{
	int ret;

	return ret;
}

int sha256_init(struct sha256_ctx *ctx)
{
	return any_result();
}

int sha256_update(struct sha256_ctx *ctx, const void *data, size_t len)
{
	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	return any_result();
}

int sha256_final(struct sha256_ctx *ctx, __u8 out[32])
{
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(out, 32);
	return any_result();
}

void sha256_free(struct sha256_ctx *ctx)
{
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(out, 32);
	return any_result();
}

int hmac_sha256(const __u8 *key, size_t key_len, const void *data,
		size_t len, __u8 out[32])
{
	__CPROVER_assert(__CPROVER_r_ok(key, key_len) &&
			 __CPROVER_r_ok(data, len), "MACs only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a MAC's room");
	__CPROVER_havoc_slice(out, 32);
	return any_result();
}

int aes128_cfb_encrypt(const __u8 key[16], const __u8 *in, size_t len,
		       __u8 *out)
{
	__CPROVER_assert(__CPROVER_r_ok(key, 16) && __CPROVER_r_ok(in, len) &&
			 __CPROVER_w_ok(out, len), "encrypts only its input");
	__CPROVER_havoc_slice(out, len);
	return any_result();
}

static __u8 *digest(void)
{
	return any_bytes(32);
}

static void policies(void)
{
	__u8 *a = digest(), *b = digest(), *name = any_bytes(TPM_NAME_LEN);
	__u8 *prev = digest(), *out = digest(), *pub = any_bytes(384);
	__u32 cc, index, attrs, hierarchy, mask;
	__u16 data_size;
	size_t n_values;
	bool written;

	__CPROVER_assume(n_values <= 24);

	if (tpm_policy_nv_written(prev, written, out) ||
	    tpm_policy_or(a, b, out) || tpm_policy_signed(prev, pub, out) ||
	    tpm_policy_command_code(prev, cc, out) ||
	    tpm_register_policy_final(a, b, pub, out) ||
	    tpm_policy_pcr(prev, mask, a, out) ||
	    tpm_register_policy(mask, any_bytes(32 * n_values), n_values, pub,
				digest(), digest(), out) ||
	    tpm_nv_name(index, attrs, prev, data_size, name) ||
	    tpm_qualified_name(hierarchy, name, any_bytes(TPM_NAME_LEN)) ||
	    tpm_nv_extend_cphash(name, prev, out))
		return;
}

static void names(void)
{
	__u8 *name = any_bytes(TPM_NAME_LEN);
	size_t len, nonce_len;

	if (!tpm_object_name(any_bytes(len), len, name))
		__CPROVER_assert(len >= 4, "a public area of type and name hash");
	if (!tpm_writer_auth_hash(any_bytes(64), nonce_len, digest(),
				  digest()))
		__CPROVER_assert(nonce_len && nonce_len <= 64,
				 "a nonce of 1 to 64 bytes");
}

static void otel(void)
{
	bool null_body, null_out;
	__u8 *body, *out;

	body = null_body ? NULL : digest();
	out = null_out ? NULL : digest();

	if (!otel_origin_digest(body, out))
		__CPROVER_assert(body && out,
				 "origin digest accepts valid body and out");
}

void harness(void)
{
	policies();
	names();
	otel();
}
