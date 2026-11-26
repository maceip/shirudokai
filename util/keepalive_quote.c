// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "keepalive_quote.h"
#include "tpm.h"

noinline_for_stack int
keepalive_quote_format(const struct tpm_attestation *att,
		       const struct tpm_key *ak, char *out, size_t cap)
{
	char attest[BASE64_SIZE(TPM_ATTEST_MAX)];
	char sig[BASE64_SIZE(TPM_SIGNATURE_MAX)];
	char public[BASE64_SIZE(TPM_PUBLIC_MAX)];
	int ret;

	ret = base64_encode(att->attest, att->attest_len, attest,
			    sizeof(attest));
	if (!ret)
		ret = base64_encode(att->signature, att->signature_len, sig,
				    sizeof(sig));
	if (!ret)
		ret = base64_encode(ak->public, ak->public_len, public,
				    sizeof(public));
	if (!ret)
		ret = strsprintf(out, cap, "attest=%s;sig=%s;ak=%s", attest,
				 sig, public);
	return min(ret, 0);
}

/*
 * The quote is over no PCR, which tells a keepalive or telemetry quote
 * from one of attest. The key is created for this quote and flushed
 * after it.
 */
noinline_for_stack int
tpm_quote_digest(const __u8 digest[CRYPTO_SHA256_LEN], struct tpm_key *ak,
		 struct tpm_attestation *att)
{
	struct tpm *tpm = NULL;
	int ret;

	ret = tpm_open(&tpm);
	if (ret)
		return ret;
	*ak = (struct tpm_key){};
	*att = (struct tpm_attestation){};
	ret = tpm_ak_create(tpm, ak);
	if (!ret)
		ret = tpm_quote(tpm, ak, digest, CRYPTO_SHA256_LEN, 0, att);
	tpm_key_flush(tpm, ak);
	tpm_close(tpm);
	return ret;
}

noinline_for_stack int
keepalive_quote(const char *body, size_t len, char *quote, size_t cap)
{
	struct tpm_attestation att = {};
	__u8 digest[CRYPTO_SHA256_LEN];
	struct tpm_key ak = {};
	int ret;

	ret = sha256_buffer(body, len, digest);
	if (ret)
		return ret;
	ret = tpm_quote_digest(digest, &ak, &att);
	if (!ret)
		ret = keepalive_quote_format(&att, &ak, quote, cap);
	return ret;
}
