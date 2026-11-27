// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

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
 * from one of attest.
 */
noinline_for_stack int
tpm_quote_session_open(struct tpm_quote_session *sess)
{
	int ret;

	if (!sess)
		return -EINVAL;
	memset(sess, 0, sizeof(*sess));
	ret = tpm_open(&sess->tpm);
	if (ret)
		return ret;
	ret = tpm_ak_create(sess->tpm, &sess->ak);
	if (ret) {
		tpm_close(sess->tpm);
		sess->tpm = NULL;
		return ret;
	}
	sess->active = true;
	return 0;
}

noinline_for_stack int
tpm_quote_session_quote(struct tpm_quote_session *sess,
			const __u8 digest[CRYPTO_SHA256_LEN],
			struct tpm_key *ak, struct tpm_attestation *att)
{
	int ret;

	if (!sess || !sess->active || !sess->tpm || !ak || !att)
		return -EINVAL;
	*ak = (struct tpm_key){};
	*att = (struct tpm_attestation){};
	ret = tpm_quote(sess->tpm, &sess->ak, digest, CRYPTO_SHA256_LEN, 0,
			att);
	if (!ret) {
		*ak = sess->ak;
		ak->handle = 0;
	}
	return ret;
}

void tpm_quote_session_close(struct tpm_quote_session *sess)
{
	if (!sess)
		return;
	if (sess->tpm) {
		if (sess->active)
			tpm_key_flush(sess->tpm, &sess->ak);
		tpm_close(sess->tpm);
	}
	memset(sess, 0, sizeof(*sess));
}

noinline_for_stack int
tpm_quote_digest(const __u8 digest[CRYPTO_SHA256_LEN], struct tpm_key *ak,
		 struct tpm_attestation *att)
{
	struct tpm_quote_session sess = {};
	int ret;

	ret = tpm_quote_session_open(&sess);
	if (ret)
		return ret;
	ret = tpm_quote_session_quote(&sess, digest, ak, att);
	tpm_quote_session_close(&sess);
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
