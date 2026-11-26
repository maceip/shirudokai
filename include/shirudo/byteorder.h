/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Byte-order conversions under the kernel's names, for userspace.
 */

#ifndef SHIRUDO_BYTEORDER_H
#define SHIRUDO_BYTEORDER_H

#include <endian.h>
#include <string.h>

#include <shirudo/compiler.h>
#include <shirudo/types.h>

/*
 * Between host order and the restricted __le and __be types; the __force
 * casts are the one place sparse lets a value change between the two.
 */
static inline __le16 cpu_to_le16(__u16 v)
{
	return (__force __le16)htole16(v);
}

static inline __le32 cpu_to_le32(__u32 v)
{
	return (__force __le32)htole32(v);
}

static inline __le64 cpu_to_le64(__u64 v)
{
	return (__force __le64)htole64(v);
}

static inline __u16 le16_to_cpu(__le16 v)
{
	return le16toh((__force __u16)v);
}

static inline __u32 le32_to_cpu(__le32 v)
{
	return le32toh((__force __u32)v);
}

static inline __u64 le64_to_cpu(__le64 v)
{
	return le64toh((__force __u64)v);
}

static inline __be16 cpu_to_be16(__u16 v)
{
	return (__force __be16)htobe16(v);
}

static inline __be32 cpu_to_be32(__u32 v)
{
	return (__force __be32)htobe32(v);
}

static inline __be64 cpu_to_be64(__u64 v)
{
	return (__force __be64)htobe64(v);
}

static inline __u16 be16_to_cpu(__be16 v)
{
	return be16toh((__force __u16)v);
}

static inline __u32 be32_to_cpu(__be32 v)
{
	return be32toh((__force __u32)v);
}

static inline __u64 be64_to_cpu(__be64 v)
{
	return be64toh((__force __u64)v);
}

/*
 * From and into bytes as they lie in a file or on the TPM's wire, at any
 * alignment: the copy is right
 * on every architecture, and the compiler makes it one load where the
 * target allows a misaligned one.
 */
static inline __u16 get_le16(const void *p)
{
	__le16 v;

	memcpy(&v, p, sizeof(v));
	return le16_to_cpu(v);
}

static inline __u32 get_le32(const void *p)
{
	__le32 v;

	memcpy(&v, p, sizeof(v));
	return le32_to_cpu(v);
}

static inline __u64 get_le64(const void *p)
{
	__le64 v;

	memcpy(&v, p, sizeof(v));
	return le64_to_cpu(v);
}

static inline __u16 get_be16(const void *p)
{
	__be16 v;

	memcpy(&v, p, sizeof(v));
	return be16_to_cpu(v);
}

static inline __u32 get_be32(const void *p)
{
	__be32 v;

	memcpy(&v, p, sizeof(v));
	return be32_to_cpu(v);
}

static inline __u64 get_be64(const void *p)
{
	__be64 v;

	memcpy(&v, p, sizeof(v));
	return be64_to_cpu(v);
}

static inline void put_be16(void *p, __u16 v)
{
	__be16 b = cpu_to_be16(v);

	memcpy(p, &b, sizeof(b));
}

static inline void put_be32(void *p, __u32 v)
{
	__be32 b = cpu_to_be32(v);

	memcpy(p, &b, sizeof(b));
}

static inline void put_be64(void *p, __u64 v)
{
	__be64 b = cpu_to_be64(v);

	memcpy(p, &b, sizeof(b));
}

#endif /* SHIRUDO_BYTEORDER_H */
