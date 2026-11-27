// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The bytes a vouch signs, for certificates of LEN bytes and a set of two
 * members, with OpenSSL's check a stub that takes the signed bytes from
 * their signer alone: `shirudo-build keys vouch` signs the prefix, its NUL
 * and the certificate, and keys_verify_vouch() of util/keys.c admits that
 * certificate under that member, and no other or longer one.
 */

/* As proof.h, before the system headers can include <ctype.h>. */
#define __NO_CTYPE 1

#include <curl/curl.h>

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/keys.c"

#define NR_MEMBERS	2

static const __u8 *vouched;
static size_t vouched_len;
static __u8 signer;

/* A member's certificate is one byte here, its place in the set. */
int cert_read_der(const __u8 *der, size_t len, struct cert *cert)
{
	cert->impl = (void *)(size_t)(der[0] + 1);
	return 0;
}

void cert_free(struct cert *cert)
{
}

int cert_validity_window(const struct cert *cert, __s64 *not_before,
			 __s64 *not_after)
{
	*not_before = 0;
	*not_after = 2000;
	return 0;
}

time_t time(time_t *out)
{
	if (out)
		*out = 1000;
	return 1000;
}

int verify_detached(const __u8 *payload, size_t payload_len,
		    const __u8 *signature, size_t signature_len,
		    const struct cert *cert)
{
	return cert->impl == (void *)(size_t)(signer + 1) &&
	       payload_len == vouched_len &&
	       !memcmp(payload, vouched, payload_len) ? 0 : -EKEYREJECTED;
}

/* As build_keys_vouch() of tools/shirudo-build/vouch.c has OpenSSL sign. */
static bool vouch(const __u8 *der)
{
	static const char prefix[] = KEYS_VOUCH_PREFIX;
	__u8 *payload = NULL;
	size_t size = 0, i;
	int ret;

	ret = keys_vouch_payload(der, LEN, &payload, &size);
	if (ret) {
		__CPROVER_assert(ret == -ENOMEM && !payload && !size,
				 "only memory fails, and leaves nothing");
		return false;
	}
	__CPROVER_assert(size == sizeof(prefix) + LEN,
			 "a payload as long as the prefix and the certificate");
	__CPROVER_assume(i < size);
	__CPROVER_assert(payload[i] == (i < sizeof(prefix) ? (__u8)prefix[i] :
					der[i - sizeof(prefix)]),
			 "the prefix, its NUL and then the certificate");
	vouched = payload;
	vouched_len = size;
	return true;
}

static bool members(struct trusted_set *set)
{
	__u8 i;

	for (i = 0; i < NR_MEMBERS; i++) {
		set->certs[i].sha256[0] = i;
		set->certs[i].fingerprint[0] = i;
		if (der_keep(set->certs[i].sha256, &i, sizeof(i)))
			return false;
	}
	set->n = NR_MEMBERS;
	return true;
}

void harness(void)
{
	const __u8 *der = any_bytes(LEN), *other = any_bytes(LEN + 1);
	struct trusted_set set = {};
	__u8 voucher[32], sig[1];
	bool same = true;
	size_t i;
	int ret;

	__CPROVER_assume(signer < NR_MEMBERS);
	if (!members(&set) || !vouch(der))
		return;
	ret = keys_verify_vouch(&set, der, LEN, sig, sizeof(sig), voucher);
	__CPROVER_assert(ret == -ENOMEM ||
			 (!ret && voucher[0] == signer),
			 "the vouch admits its certificate under its signer");
	for (i = 0; i < LEN; i++)
		same &= other[i] == der[i];
	ret = keys_verify_vouch(&set, other, LEN, sig, sizeof(sig), voucher);
	__CPROVER_assert(ret == -ENOMEM ||
			 ret == (same ? 0 : -EKEYREJECTED),
			 "and no other certificate of its length");
	ret = keys_verify_vouch(&set, other, LEN + 1, sig, sizeof(sig),
				voucher);
	__CPROVER_assert(ret == -ENOMEM || ret == -EKEYREJECTED,
			 "nor a longer one");
}
