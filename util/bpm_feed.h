/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Curated signed CVE shield feed: schema parser, canonical emitter and
 * ML-DSA-87 detached CMS signature verification.
 */

#ifndef SHIRUDO_BPM_FEED_H
#define SHIRUDO_BPM_FEED_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/compiler.h>
#include <shirudo/misc.h>

#include "bpm_oci.h"
#include "bpm_tree.h"
#include "crypto.h"

#define BPM_FEED_MAX_ENTRIES	512
#define BPM_FEED_MAX_CVES	32
#define BPM_FEED_CVE_MAX	32
#define BPM_FEED_TIME_MAX	32
#define BPM_FEED_DESC_MAX	512

enum bpm_feed_role {
	BPM_FEED_ROLE_NONE = 0,
	BPM_FEED_ROLE_MITIGATION = 1,
	BPM_FEED_ROLE_DETECTOR = 2,
};

struct bpm_feed_entry {
	char			id[TREE_STRING_MAX];
	char			cves[BPM_FEED_MAX_CVES][BPM_FEED_CVE_MAX];
	int			n_cves;
	char			package[BPM_MAX_NAME];
	char			version[BPM_MAX_NAME];
	char			reference[BPM_MAX_ENDPOINT];
	char			manifest_digest[BPM_MAX_DIGEST];
	enum bpm_feed_role	role;
	struct tree_selector	selector;
	char			description[BPM_FEED_DESC_MAX];
};

struct bpm_feed {
	int			schema;
	char			feed_id[TREE_STRING_MAX];
	char			generated_at[BPM_FEED_TIME_MAX];
	struct bpm_feed_entry	*entries;
	int			entries_capacity;
	int			n_entries;
};

bool bpm_feed_cve_ok(const char *cve);
const char *bpm_feed_role_str(enum bpm_feed_role role);
bool bpm_feed_entry_has_cve(const struct bpm_feed_entry *entry,
			    const char *cve);

int bpm_feed_parse(const char *body, size_t len,
		   struct bpm_feed *out) __must_check;
int bpm_feed_emit(const struct bpm_feed *feed,
		  char **out, size_t *out_len) __must_check;
void bpm_feed_free(struct bpm_feed *feed);

/*
 * Verify a detached ML-DSA-87 CMS signature over feed_bytes against cert
 * before parsing the feed document. Returns -EKEYREJECTED when cert is
 * not ML-DSA-87 or the signature does not verify, and -EINVAL on a
 * malformed document.
 */
int bpm_feed_verify_memory(const __u8 *feed_bytes, size_t feed_len,
			   const __u8 *sig_bytes, size_t sig_len,
			   const struct cert *cert,
			   struct bpm_feed *out) __must_check;
int bpm_feed_verify_files(const char *feed_path, const char *sig_path,
			  const char *cert_path,
			  struct bpm_feed *out) __must_check;

#endif /* SHIRUDO_BPM_FEED_H */
