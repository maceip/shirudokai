// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "crypto.h"
#include "hex.h"
#include "unit.h"

static void fips_mode_init_is_fail_closed_and_consistent(void)
{
	bool before = crypto_fips_enabled();
	int ret;

	ret = crypto_fips_init();
	if (ret == 0) {
		EXPECT_TRUE(crypto_fips_enabled());
		EXPECT_EQ(crypto_fips_init(), 0);
	} else {
		EXPECT_EQ(ret, -ENOPKG);
		EXPECT_EQ(crypto_fips_enabled(), before);
	}
}

static void hmac_sha256_matches_rfc_4231_test_case_2(void)
{
	static const char want[] =
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
	static const __u8 key[] = "Jefe";
	static const __u8 msg[] = "what do ya want for nothing?";
	char hex[2 * CRYPTO_SHA256_LEN + 1];
	__u8 mac[CRYPTO_SHA256_LEN];

	ASSERT_EQ(hmac_sha256(key, sizeof(key) - 1, msg, sizeof(msg) - 1, mac),
		  0);
	hex_encode(mac, sizeof(mac), hex);
	EXPECT_STREQ(hex, want);
}

static void aes128_cfb_encrypt_matches_nist_zero_iv_block(void)
{
	static const char key_hex[] = "2b7e151628aed2a6abf7158809cf4f3c";
	static const char pt_hex[] = "6bc1bee22e409f96e93d7e117393172a";
	static const char ct_hex[] = "1636d5ee34f80625d77f8e56ca884345";
	__u8 key[16], pt[16], ct[16], want[16];

	ASSERT_EQ(hex_decode(key_hex, key, sizeof(key)), 0);
	ASSERT_EQ(hex_decode(pt_hex, pt, sizeof(pt)), 0);
	ASSERT_EQ(hex_decode(ct_hex, want, sizeof(want)), 0);
	ASSERT_EQ(aes128_cfb_encrypt(key, pt, sizeof(pt), ct), 0);
	EXPECT_MEMEQ(ct, want, sizeof(want));
}

static const struct unit_case cases[] = {
	UNIT_CASE(fips_mode_init_is_fail_closed_and_consistent),
	UNIT_CASE(hmac_sha256_matches_rfc_4231_test_case_2),
	UNIT_CASE(aes128_cfb_encrypt_matches_nist_zero_iv_block),
	{}
};

UNIT_SUITE(crypto, cases);
