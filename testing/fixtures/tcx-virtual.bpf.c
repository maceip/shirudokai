// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tcx/ingress/2")
int tcx_virtual(struct __sk_buff *skb)
{
	return TCX_NEXT;
}

char _license[] SEC("license") = "Dual BSD/GPL";
