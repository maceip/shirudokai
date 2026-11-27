/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The shirudo.quote of a keepalive: the attestation key's quote of the
 * SHA-256 of the body, as the attest, sig and ak fields in base64.
 */

#ifndef SHIRUDO_KEEPALIVE_QUOTE_H
#define SHIRUDO_KEEPALIVE_QUOTE_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "crypto.h"
#include "tpm.h"

/* Holds the longest quote and its terminator. */
#define KEEPALIVE_QUOTE_MAX	(sizeof("attest=;sig=;ak=") +		\
				 BASE64_SIZE(TPM_ATTEST_MAX) +		\
				 BASE64_SIZE(TPM_SIGNATURE_MAX) +	\
				 BASE64_SIZE(TPM_PUBLIC_MAX))

/*
 * Writes attest=<TPMS_ATTEST>;sig=<TPMT_SIGNATURE>;ak=<TPMT_PUBLIC> in
 * padded base64 with its terminator. -E2BIG when cap does not hold it.
 */
int keepalive_quote_format(const struct tpm_attestation *att,
			   const struct tpm_key *ak, char *out,
			   size_t cap) __must_check;

struct tpm_quote_session {
	struct tpm	*tpm;
	struct tpm_key	ak;
	bool		active;
};

/*
 * Open one TPM session and create an attestation key for repeated
 * quotes in a single invocation, then flush and close on completion.
 */
int tpm_quote_session_open(struct tpm_quote_session *sess) __must_check;
int tpm_quote_session_quote(struct tpm_quote_session *sess,
			    const __u8 digest[CRYPTO_SHA256_LEN],
			    struct tpm_key *ak,
			    struct tpm_attestation *att) __must_check;
void tpm_quote_session_close(struct tpm_quote_session *sess);

/*
 * Quotes digest with the attestation key of tpm_ak_create() over no PCR,
 * filling *ak and *att and flushing the key before closing the TPM.
 */
int tpm_quote_digest(const __u8 digest[CRYPTO_SHA256_LEN],
		     struct tpm_key *ak,
		     struct tpm_attestation *att) __must_check;

/*
 * Quotes the SHA-256 of the body with the attestation key of
 * tpm_ak_create() over no PCR and writes the quote as
 * keepalive_quote_format() does.
 */
int keepalive_quote(const char *body, size_t len, char *quote,
		    size_t cap) __must_check;

#endif /* SHIRUDO_KEEPALIVE_QUOTE_H */
