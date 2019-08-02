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
#include <linux/pyronia_internal.h>
#include <uapi/linux/pyronia.h>

#include "include/pyronia.h"
#include "include/stack_logging.h"
#include "include/lib_policy.h"

static struct crypto_shash *sl_tfm;
static struct stack_hash *pending_user_hash;

int init_stack_logging_hash() {
  struct crypto_shash *tfm;

  if (!pyronia_initialized)
    return 0;
  
  tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
  if (IS_ERR(tfm)) {
    int error = PTR_ERR(tfm);
    PYR_ERROR("failed to setup stack logging sha256 hashing: %d\n", error);
    return error;
  }
  sl_tfm = tfm;
  printk(KERN_ERR "[%s] done\n", __func__);

  pending_user_hash = NULL;
  
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
    printk("[%s] resulting hash: ", __func__);
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
      //print_hash(hash);
    }

 out:
    return err;
}

int log_callstack_hash(unsigned char *hash, u32 perms,
                       struct pyr_acl_entry *entry) {
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
    entry->logged_stack_hashes[log_idx].perms = perms;
    entry->num_logged_hashes++;
    err = 0;

 out:
    return err;
}

int verify_callstack_hash(struct pyr_acl_entry *entry, u32 *perms) {
    int match = 0;
    int i = 0;
    u32 hperms = 0;
    if (pending_user_hash) {
        PYR_DEBUG(KERN_ERR "[%s] Have hash for resource %s\n", __func__, entry->resource);
	for (i = 0; i < entry->num_logged_hashes; i++) {
	  if (!memcmp(pending_user_hash, entry->logged_stack_hashes[i].h, SHA256_DIGEST_SIZE)) {
	    match = 1;
	    hperms = entry->logged_stack_hashes[i].perms;
	    break;
	  }
	}
        kvfree(pending_user_hash);
        pending_user_hash = NULL;
    }
    *perms = hperms;
    return match;
}

/** Copy the userspace hash pointed to by the resource pointer
 * into a kernelspace buffer, and extracts the requested resource
 * from the resource pointer.
 */
int copy_userspace_stack_hash(void __user **resourcep,
                                enum pyr_user_resource resource_type) {
    int copied = 0;
    struct pyr_userspace_stack_hash __user *uh = NULL;
    struct stack_hash *pending_hash = NULL;
    char dummy_str[128]; //used to test if the resource

    // ignore all of this if we're not in a process using Pyronia
    if (!current || !current->mm || current->mm->using_smv == 0 || !pyronia_initialized)
      return 0;
    
    uh = (struct pyr_userspace_stack_hash __user *)*resourcep;
    if (uh == NULL) {
        printk(KERN_CRIT "[%s] NULL resource", __func__);
        goto out;
    }

    PYR_DEBUG("[%s] uh addr %p\n", __func__, uh);
    
    // let's parse out the requested resource either way
    switch(resource_type) {
    case FILENAME_RESOURCE:
        if (uh->resource.filename == NULL)
            goto out;
	memset(dummy_str, 0, 128);
	copied = strncpy_from_user(dummy_str, (const char __user *)uh->resource.filename, 128);
	if (copied < 0) {
	  PYR_DEBUG("[%s] Given filename %s\n", __func__, (const char __user *)*resourcep);
	  copied = 0;
	  goto out;
	}
        *resourcep = (void __user *)uh->resource.filename;
	PYR_DEBUG("[%s] Extracted filename %s\n", __func__, (const char __user *)*resourcep);
        break;
    case SOCKADDR_RESOURCE:
        if (uh->resource.addr == NULL)
            goto out;
        *resourcep = (void __user *)uh->resource.addr;
	PYR_DEBUG("[%s] Got addr %p\n", __func__, uh->resource.addr);
        break;
    default:
        printk(KERN_ERR "[%s] Unknown userspace resource type\n", __func__);
        goto out;
    }

    if (!uh->includes_stack)
        goto out;

    PYR_DEBUG(KERN_ERR "[%s] resource includes hash\n", __func__);

    if (pending_hash) {
        printk(KERN_CRIT "[%s] Ignoring new incoming hash\n", __func__);
        goto out;
    }
    
    // copy hash over
    pending_hash = kvzalloc(sizeof(struct stack_hash));
    if (!pending_hash)
        goto out;

    if (copy_from_user(pending_hash->h, uh->hash, SHA256_DIGEST_SIZE))
        goto out;

    pending_hash->perms = 0;
    //print_hash(pending_hash->h);
    pending_user_hash = pending_hash;
    copied = 1;
 out:
    return copied;
}
