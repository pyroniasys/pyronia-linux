/*
 * Pyronia security module
 *
 * Implements the Pyronia stack logging definitions.
 *
 * Copyright (C) 2019 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include "include/stack_logging.h"
#include "include/lib_policy.h"

static inline int generate_sha256(unsigned char *data, size_t len,
                                  unsigned char **hash) {
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;

    if (!hash) {
        printk(KERN_ERR "[%s] Need hash destination\n", __func__);
        return -1;
    }
    memset(*hash, 0, SHA256_DIGEST_SIZE);

    tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_HASH);

    desc.tfm = tfm;
    desc.flags = 0;

    sg_init_one(&sg, data, len);
    crypto_hash_init(&desc);

    crypto_hash_update(&desc, &sg, len);
    crypto_hash_final(&desc, *hash);
    crypto_free_hash(tfm);

    return 0;
}

static inline void print_hash(unsigned char *hash) {
    int i = 0;
    printk(KERN_ERR "[%s] resulting hash: ", __func__);
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printk(KERN_ERR "%02x", hash[i]);
    }
    printk(KERN_ERR "\n");
}

int compute_callstack_hash(char *stack_str, unsigned char *hash) {
    int err = -1;

    if (!stack_str) {
        printk(KERN_CRIT "[%s] No stack string\n", __func__);
        goto out;
    }

    err = generate_sha256((unsigned char *)stack_str, strlen(stack_str),
                          &hash);
    if (!err) {
        print_hash(hash);
    }

 out:
    return err;
}

int log_callstack_hash(unsigned char *hash, struct pyr_acl_entry *entry) {
    int err = -1;
    int log_idx = -1;

    if (!entry) {
        printk(KERN_CRIT "[%s] No ACL entry\n", __func__);
        goto out;
    }

    log_idx = entry->num_logged_hashes;
    if (log_idx == MAX_LOGGED_HASHES) {
        printk(KERN_CRIT "[%s] Reached maximum allowable number of logged hashes for this ACL entry\n", __func__);
        goto out;
    }

    if (entry->logged_stack_hashes[log_idx] != NULL) {
        printk(KERN_CRIT "[%s] Trying to override an existing logged hash\n", __func__);
        goto out;
    }

    memcpy(entry->logged_stack_hashes[log_idx].h, hash, SHA256_DIGEST_SIZE);
    entry->num_logged_hashes++;
    err = 0;

 out:
    return err;
}

int verify_callstack_hash(unsigned char *recv_hash, struct pyr_acl_entry *entry) {
    return 0;
}
