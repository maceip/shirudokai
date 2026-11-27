/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Cloud vTPM endorsement key public-key parsing and template matching
 * (AWS NitroTPM, GCP Shielded VM).
 */

#ifndef SHIRUDO_EK_CLOUD_H
#define SHIRUDO_EK_CLOUD_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "tpm_wire.h"

#define EK_CLOUD_MAX	(16 * 1024)

enum ek_template {
	EK_TEMPLATE_POLICY_A,
	EK_TEMPLATE_POLICY_B,
};

enum ek_cloud_format {
	EK_CLOUD_TPM2B,
	EK_CLOUD_SPKI,
};

struct ek_cloud_key {
	enum ek_cloud_format	format;
	bool			rsa;
	struct tpm_public	tpm_pub;
	__u8			tpmt[TPM_PUBLIC_MAX];
	size_t			tpmt_len;
	__u8			name[TPM_NAME_MAX];
	__u8			n[256];
	size_t			n_len;
	__u32			e;
	__u8			x[32];
	__u8			y[32];
};

bool ek_low_range_template_valid(const struct tpm_public *pub);
bool ek_cloud_template_valid(const struct tpm_public *pub);

int ek_cloud_parse(const void *data, size_t len,
		   struct ek_cloud_key *out) __must_check;

int ek_cloud_build_public(const struct ek_cloud_key *key,
			  enum ek_template tmpl,
			  struct tpm_public *pub,
			  __u8 tpmt[TPM_PUBLIC_MAX],
			  size_t *tpmt_len,
			  __u8 name[TPM_NAME_MAX]) __must_check;

int ek_cloud_name(const void *cloud_pub, size_t cloud_len,
		  enum ek_template tmpl, bool force_template,
		  bool *out_rsa, enum ek_template *out_tmpl,
		  __u8 out_ek_name[TPM_NAME_MAX]) __must_check;

int ek_cloud_verify_presented(const void *cloud_pub, size_t cloud_len,
			      const void *presented_tpm2b,
			      size_t presented_len,
			      __u8 out_ek_name[TPM_NAME_MAX],
			      size_t *out_ek_name_len) __must_check;

#endif /* SHIRUDO_EK_CLOUD_H */
