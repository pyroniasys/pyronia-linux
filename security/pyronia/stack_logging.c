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
#include <crypto/hash.h>

#include "include/pyronia.h"
#include "include/stack_logging.h"
#include "include/lib_policy.h"

static struct crypto_shash *sl_tfm;

int init_stack_logging_hash() {
  struct crypto_shash *tfm;

  tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_TYPE_SHASH);
  if (IS_ERR(tfm)) {
    int error = PTR_ERR(tfm);
    PYR_ERROR("failed to setup profile sha1 hashing: %d\n", error);
    return error;
  }
  sl_tfm = tfm;
  printk(KERN_ERR "[%s] done\n", __func__);
  
  return 0;
}

static inline int generate_sha256(unsigned char *data, size_t len,
                                  unsigned char **hash) {
  int err = -1;
  struct {
    struct shash_desc shash;
    char ctx[crypto_shash_descsize(sl_tfm)];
  } desc;

    if (!sl_tfm)
        goto out;
  
    if (!hash) {
        printk(KERN_ERR "[%s] Need hash destination\n", __func__);
	goto out;
    }
    memset(*hash, 0, SHA256_DIGEST_SIZE);

    desc.shash.tfm = sl_tfm;
    desc.shash.flags = 0;

    err = crypto_shash_init(&desc.shash);
    if (err) {
      printk(KERN_ERR "[%s] Could not init shash\n", __func__);
      goto out;
    } 

    err = crypto_shash_update(&desc.shash, data, len);
    if (err) {
      printk(KERN_ERR "[%s] Could not update shash\n", __func__);
      goto out;
    }
    
    err = crypto_shash_final(&desc.shash, *hash);
    if (err) {
      printk(KERN_ERR "[%s] Could not finalize shash\n", __func__);
      goto out;
    }

 out:
    return err;
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

    memset(entry->logged_stack_hashes[log_idx].h, 0, SHA256_DIGEST_SIZE);
    memcpy(entry->logged_stack_hashes[log_idx].h, hash, SHA256_DIGEST_SIZE);
    entry->num_logged_hashes++;
    err = 0;

 out:
    return err;
}

int verify_callstack_hash(unsigned char *recv_hash, struct pyr_acl_entry *entry) {
    return 0;
}
