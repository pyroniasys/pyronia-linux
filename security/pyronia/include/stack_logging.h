/*
 * Pyronia security module
 *
 * This file contains Pyronia stack logging definitions.
 *
 * Copyright (C) 2019 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_STACKLOGGING_H
#define __PYR_STACKLOGGING_H

#include <linux/types.h>
#include <crypto/sha.h>

#define MAX_LOGGED_HASHES 16

typedef struct stack_hash {
    unsigned char h[SHA256_DIGEST_SIZE];
    u32 perms;
} stack_hash_t;

// forward declare
struct pyr_acl_entry;

int init_stack_logging_hash(void);
int compute_callstack_hash(char *, unsigned char *);
int log_callstack_hash(unsigned char *, u32, struct pyr_acl_entry *);
int verify_callstack_hash(struct pyr_acl_entry *, u32 *);

#endif /* __PYR_STACKLOGGING_H */
