// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_feed_parse() on a curated CVE shield feed, canonical round-trip
 * emission through bpm_feed_emit(), and CVE query consistency.
 */

#include <stdlib.h>
#include <string.h>

#include "fuzz.h"

#include "bpm_feed.h"
#include "malloc.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char *out = NULL, *out2 = NULL;
	struct bpm_feed feed, again;
	size_t len = 0, len2 = 0;

	if (bpm_feed_parse((const char *)data, size, &feed))
		return 0;
	if (bpm_feed_emit(&feed, &out, &len))
		abort();
	if (bpm_feed_parse(out, len, &again))
		abort();
	if (again.schema != feed.schema ||
	    strcmp(again.feed_id, feed.feed_id) ||
	    strcmp(again.generated_at, feed.generated_at) ||
	    again.n_entries != feed.n_entries)
		abort();
	for (int i = 0; i < feed.n_entries; i++) {
		const struct bpm_feed_entry *a = &feed.entries[i];
		const struct bpm_feed_entry *b = &again.entries[i];

		if (strcmp(a->id, b->id) || a->n_cves != b->n_cves ||
		    a->role != b->role ||
		    !bpm_feed_entry_has_cve(b, a->cves[0]))
			abort();
	}
	if (bpm_feed_emit(&again, &out2, &len2))
		abort();
	if (len != len2 || memcmp(out, out2, len))
		abort();
	xfree(out2, len2);
	xfree(out, len);
	bpm_feed_free(&again);
	bpm_feed_free(&feed);
	return 0;
}
