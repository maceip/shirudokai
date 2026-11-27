// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The checks a backend runs on a keepalive quote: the attestation key
 * signed it as an endorsement primary, and it covers the SHA-256 of the
 * body the record carries.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "json.h"
#include "row.h"

enum {
	FIELD_ATTEST,
	FIELD_SIG,
	FIELD_AK,
	FIELD_BODY_SHA256,
	FIELD_COUNT,
};

enum {
	OTEL_FIELD_AK_NAME,
	OTEL_FIELD_ATTEST,
	OTEL_FIELD_SIG,
	OTEL_FIELD_AK,
	OTEL_FIELD_BODY_SHA256,
	OTEL_FIELD_COUNT,
};

struct field {
	const char	*text;
	size_t		len;
};

static bool row_split_n(const char *row, size_t len, struct field *fields,
			size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		const char *tab = memchr(row, '\t', len);
		bool last = i == count - 1;

		if (last != !tab)
			return false;
		fields[i].text = row;
		fields[i].len = tab ? (size_t)(tab - row) : len;
		if (tab) {
			len -= fields[i].len + 1;
			row = tab + 1;
		}
	}
	return true;
}

static bool row_split(const char *row, size_t len,
		      struct field fields[FIELD_COUNT])
{
	return row_split_n(row, len, fields, FIELD_COUNT);
}

/*
 * OpenSSL's decoder skips white space and stops at a '-', so only a
 * field that encodes back to itself is standard base64 with padding.
 */
static int base64_field(const struct field *field,
			__u8 *out, size_t cap, size_t *len)
{
	__u8 bytes[BASE64_LEN(TPM_ATTEST_MAX) / 4 * 3];
	char again[BASE64_LEN(TPM_ATTEST_MAX) + 1];

	if (field->len > BASE64_LEN(cap) ||
	    base64_decode(field->text, field->len, bytes, sizeof(bytes),
			  len) ||
	    *len > cap ||
	    base64_encode(bytes, *len, again, sizeof(again)) ||
	    strlen(again) != field->len ||
	    memcmp(again, field->text, field->len))
		return -EINVAL;
	memcpy(out, bytes, *len);
	return 0;
}

static int body_sha256_field(const struct field *field,
			     __u8 out[TPM_DIGEST_LEN])
{
	char hex[QUOTE_BODY_HEX_LEN + 1];

	if (field->len != QUOTE_BODY_HEX_LEN)
		return -EINVAL;
	memcpy(hex, field->text, QUOTE_BODY_HEX_LEN);
	hex[QUOTE_BODY_HEX_LEN] = '\0';
	return hex_decode(hex, out, TPM_DIGEST_LEN);
}

static bool ak_is_p256_ecdsa(const struct tpm_public *ak)
{
	return ak->type == TPM_ALG_ECC && ak->curve == TPM_ECC_NIST_P256 &&
	       ak->scheme == TPM_ALG_ECDSA &&
	       ak->scheme_hash == TPM_ALG_SHA256;
}

/*
 * shirudo attest signs its quotes with the same key over a nonce the
 * caller chooses and refuses an empty PCR selection, so the empty one
 * is what makes a quote a keepalive's.
 */
static bool attest_is_keepalive_quote(const struct tpm_attest *attest)
{
	return attest->type == TPM_ST_ATTEST_QUOTE && !attest->pcr_mask;
}

static int quote_verify_digest(const __u8 *attest, size_t attest_len,
			       const __u8 *sig, size_t sig_len,
			       const __u8 expected[TPM_DIGEST_LEN],
			       struct quote_result *res)
{
	struct tpm_attest quote;
	struct tpm_public ak;
	bool signer;
	int ret;

	if (tpm_public_parse(res->ak_public, res->ak_public_len, &ak) ||
	    !ak_is_p256_ecdsa(&ak))
		return 0;
	if (tpm_attest_parse(attest, attest_len, &quote) ||
	    !attest_is_keepalive_quote(&quote))
		return 0;

	ret = tpm_object_name(res->ak_public, res->ak_public_len,
			      res->ak_name);
	if (!ret)
		ret = tpm_attest_signer(&quote, res->ak_name, &signer);
	if (ret)
		return ret;
	if (!signer) {
		res->verdict = QUOTE_BAD_SIGNATURE;
		return 0;
	}

	ret = tpm_attest_verify(attest, attest_len, sig, sig_len, ak.x, ak.y);
	if (ret == -EBADMSG)
		return 0;
	if (ret == -EKEYREJECTED) {
		res->verdict = QUOTE_BAD_SIGNATURE;
		return 0;
	}
	if (ret)
		return ret;

	if (quote.extra_len != TPM_DIGEST_LEN ||
	    memcmp(quote.extra, expected, TPM_DIGEST_LEN)) {
		res->verdict = QUOTE_BODY_MISMATCH;
		return 0;
	}
	res->verdict = QUOTE_OK;
	res->reset_count = quote.reset_count;
	res->restart_count = quote.restart_count;
	res->clock = quote.clock;
	return 0;
}

int quote_row_check(const char *row, size_t len, struct quote_result *res)
{
	__u8 attest[TPM_ATTEST_MAX], sig[TPM_SIGNATURE_MAX];
	__u8 body_sha256[TPM_DIGEST_LEN];
	struct field fields[FIELD_COUNT];
	size_t attest_len, sig_len;

	memset(res, 0, sizeof(*res));
	res->verdict = QUOTE_MALFORMED;
	if (!row_split(row, len, fields) ||
	    base64_field(&fields[FIELD_ATTEST], attest, sizeof(attest),
			 &attest_len) ||
	    base64_field(&fields[FIELD_SIG], sig, sizeof(sig), &sig_len) ||
	    base64_field(&fields[FIELD_AK], res->ak_public,
			 sizeof(res->ak_public), &res->ak_public_len) ||
	    body_sha256_field(&fields[FIELD_BODY_SHA256], body_sha256))
		return 0;
	return quote_verify_digest(attest, attest_len, sig, sig_len,
				   body_sha256, res);
}

int quote_otel_check(const struct quote_otel_envelope *env,
		     struct quote_result *res)
{
	__u8 attest[TPM_ATTEST_MAX], sig[TPM_SIGNATURE_MAX];
	__u8 claimed_name[TPM_NAME_LEN], origin[TPM_DIGEST_LEN];
	size_t attest_len, sig_len, name_len, ak_len;
	int ret;

	if (!res)
		return -EINVAL;
	memset(res, 0, sizeof(*res));
	res->verdict = QUOTE_MALFORMED;
	if (!env || !env->attest_hex || !env->sig_hex || !env->ak_public_hex ||
	    !env->body_sha256)
		return 0;
	if (hex_decode_max(env->attest_hex, attest, sizeof(attest),
			   &attest_len) || !attest_len ||
	    hex_decode_max(env->sig_hex, sig, sizeof(sig), &sig_len) ||
	    !sig_len ||
	    hex_decode_max(env->ak_public_hex, res->ak_public,
			   sizeof(res->ak_public), &ak_len) || !ak_len)
		return 0;
	if (env->ak_name_hex &&
	    (hex_decode_max(env->ak_name_hex, claimed_name,
			    sizeof(claimed_name), &name_len) ||
	     name_len != TPM_NAME_LEN))
		return 0;
	if (otel_origin_digest(env->body_sha256, origin))
		return 0;
	res->ak_public_len = ak_len;
	ret = quote_verify_digest(attest, attest_len, sig, sig_len, origin,
				  res);
	if (ret)
		return ret;
	if (env->ak_name_hex && res->verdict != QUOTE_MALFORMED &&
	    memneq_explicit(claimed_name, res->ak_name, TPM_NAME_LEN)) {
		res->verdict = QUOTE_BAD_SIGNATURE;
		return 0;
	}
	return 0;
}

int quote_otel_row_check(const char *row, size_t len, struct quote_result *res)
{
	char attest_hex[QUOTE_ATTEST_HEX_MAX + 1];
	char sig_hex[QUOTE_SIG_HEX_MAX + 1];
	char ak_name_hex[QUOTE_AK_NAME_HEX_LEN + 1];
	char ak_hex[QUOTE_AK_HEX_MAX + 1];
	__u8 body_sha256[TPM_DIGEST_LEN];
	struct field fields[OTEL_FIELD_COUNT];
	struct quote_otel_envelope env = {};

	if (!res)
		return -EINVAL;
	memset(res, 0, sizeof(*res));
	res->verdict = QUOTE_MALFORMED;
	if (!row_split_n(row, len, fields, OTEL_FIELD_COUNT) ||
	    fields[OTEL_FIELD_AK_NAME].len != QUOTE_AK_NAME_HEX_LEN ||
	    span_to_str(ak_name_hex, sizeof(ak_name_hex),
			fields[OTEL_FIELD_AK_NAME].text,
			fields[OTEL_FIELD_AK_NAME].len) ||
	    span_to_str(attest_hex, sizeof(attest_hex),
			fields[OTEL_FIELD_ATTEST].text,
			fields[OTEL_FIELD_ATTEST].len) ||
	    span_to_str(sig_hex, sizeof(sig_hex),
			fields[OTEL_FIELD_SIG].text,
			fields[OTEL_FIELD_SIG].len) ||
	    span_to_str(ak_hex, sizeof(ak_hex),
			fields[OTEL_FIELD_AK].text,
			fields[OTEL_FIELD_AK].len) ||
	    body_sha256_field(&fields[OTEL_FIELD_BODY_SHA256], body_sha256))
		return 0;
	env.ak_name_hex = ak_name_hex;
	env.attest_hex = attest_hex;
	env.sig_hex = sig_hex;
	env.ak_public_hex = ak_hex;
	env.body_sha256 = body_sha256;
	return quote_otel_check(&env, res);
}

static const char *const reject_reason[] = {
	[QUOTE_BAD_SIGNATURE]	= "bad_signature",
	[QUOTE_BODY_MISMATCH]	= "body_mismatch",
	[QUOTE_MALFORMED]	= "malformed",
};

static int emit_accept(struct json_emit *e, const struct quote_result *res)
{
	char ak_public[BASE64_LEN(TPM_PUBLIC_MAX) + 1];
	char ak_name[2 * TPM_NAME_LEN + 1];
	int ret;

	ret = base64_encode(res->ak_public, res->ak_public_len, ak_public,
			    sizeof(ak_public));
	if (ret)
		return ret;
	hex_encode(res->ak_name, sizeof(res->ak_name), ak_name);
	json_kv_int(e, "ok", 1);
	json_kv_string(e, "ak_name", ak_name);
	json_kv_string(e, "ak_public", ak_public);
	json_kv_int(e, "reset_count", res->reset_count);
	json_kv_int(e, "restart_count", res->restart_count);
	json_kv_u64(e, "clock", res->clock);
	return 0;
}

int quote_row_emit(const struct quote_result *res, char *line, size_t cap)
{
	struct json_emit e = { .buf = line, .cap = cap };
	int ret = 0;

	json_obj_open(&e);
	if (res->verdict == QUOTE_OK) {
		ret = emit_accept(&e, res);
	} else if ((size_t)res->verdict < ARRAY_SIZE(reject_reason)) {
		json_kv_int(&e, "ok", 0);
		json_kv_string(&e, "reason", reject_reason[res->verdict]);
	} else {
		ret = -EINVAL;
	}
	json_obj_close(&e);
	return ret ? ret : e.err;
}
