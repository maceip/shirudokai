/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Monotonic security.epoch floor for signed configuration updates.
 */

#ifndef SHIRUDO_FRESHNESS_H
#define SHIRUDO_FRESHNESS_H

#include <shirudo/compiler.h>
#include <shirudo/misc.h>

/*
 * Read the persisted monotonic epoch floor at path or under dir_fd. A
 * missing file sets *floor to 0 and returns 0; an empty or malformed file
 * returns -EUCLEAN.
 */
int freshness_read_floor(const char *path, __u64 *floor) __must_check;
int freshness_read_floor_at(int dir_fd, __u64 *floor) __must_check;

/*
 * Verify that candidate_epoch is at least the persisted floor. Returns
 * -ESTALE when candidate_epoch regresses below the floor.
 */
int freshness_verify(const char *path, __u64 candidate_epoch) __must_check;
int freshness_verify_at(int dir_fd, __u64 candidate_epoch) __must_check;

/*
 * Verify candidate_epoch against the floor and atomically persist the new
 * sealed floor when candidate_epoch advances above it.
 */
int freshness_advance(const char *path, __u64 candidate_epoch) __must_check;
int freshness_advance_at(int dir_fd, __u64 candidate_epoch) __must_check;

#endif /* SHIRUDO_FRESHNESS_H */
