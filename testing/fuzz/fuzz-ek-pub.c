// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Cloud vTPM endorsement key public-key formats (PEM SPKI, DER SPKI, raw
 * and base64 TPM2B_PUBLIC) and presented-key template matching.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/byteorder.h>

#include "ek_cloud.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	__u8 tpmt1[TPM_PUBLIC_MAX], tpmt2[TPM_PUBLIC_MAX];
	__u8 tpm2b[2 + TPM_PUBLIC_MAX], tampered[2 + TPM_PUBLIC_MAX];
	__u8 name1[TPM_NAME_MAX], name2[TPM_NAME_MAX], vname[TPM_NAME_MAX];
	struct tpm_public pub1, pub2;
	struct ek_cloud_key key;
	size_t len1 = 0, len2 = 0, vlen = 0, half;

	if (!ek_cloud_parse(data, size, &key)) {
		if (key.rsa && (key.n_len != 256 || !(key.n[0] & 0x80) ||
				key.e != 65537))
			abort();
		if (ek_cloud_build_public(&key, EK_TEMPLATE_L1, &pub1, tpmt1,
					  &len1, name1) ||
		    ek_cloud_build_public(&key, EK_TEMPLATE_L2, &pub2, tpmt2,
					  &len2, name2))
			abort();
		if (name1[0] != 0x00 || name1[1] != 0x0b ||
		    name2[0] != 0x00 || name2[1] != 0x0b ||
		    !memcmp(name1, name2, TPM_NAME_LEN))
			abort();
		if (key.format == EK_CLOUD_SPKI) {
			tpm_put2b(tpm2b, tpmt1, len1);
			if (ek_cloud_verify_presented(data, size, tpm2b,
						      2 + len1, vname, &vlen) ||
			    vlen != TPM_NAME_LEN ||
			    memcmp(vname, name1, TPM_NAME_LEN))
				abort();
			memcpy(tampered, tpm2b, 2 + len1);
			tampered[2 + len1 - 1] ^= 0x01;
			if (!ek_cloud_verify_presented(data, size, tampered,
						       2 + len1, vname, &vlen))
				abort();
		} else {
			tpm_put2b(tpm2b, key.tpmt, key.tpmt_len);
			if (ek_cloud_verify_presented(data, size, tpm2b,
						      2 + key.tpmt_len, vname,
						      &vlen) ||
			    vlen != TPM_NAME_LEN ||
			    memcmp(vname, key.name, TPM_NAME_LEN))
				abort();
		}
	}

	if (size >= 4) {
		half = size / 2;
		if (!ek_cloud_verify_presented(data, half, data + half,
					       size - half, vname, &vlen) &&
		    (vlen != TPM_NAME_LEN || vname[0] != 0x00 ||
		     vname[1] != 0x0b))
			abort();
	}
	return 0;
}
