/*
 * AppArmor security module
 *
 * This file contains AppArmor policy loading interface function definitions.
 *
 * Copyright 2013 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * Fns to provide a checksum of policy that has been loaded this can be
 * compared to userspace policy compiles to check loaded policy is what
 * it should be.
 */

#include <crypto/hash.h>

#include "include/pyronia.h"
#include "include/crypto.h"

static unsigned int pyronia_hash_size;

static struct crypto_shash *pyronia_tfm;

unsigned int pyr_hash_size(void)
{
	return pyronia_hash_size;
}

int pyr_calc_profile_hash(struct pyr_profile *profile, u32 version, void *start,
			 size_t len)
{
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(pyronia_tfm)];
	} desc;
	int error = -ENOMEM;
	u32 le32_version = cpu_to_le32(version);

	if (!pyr_g_hash_policy)
		return 0;

	if (!pyronia_tfm)
		return 0;

	profile->hash = kzalloc(pyronia_hash_size, GFP_KERNEL);
	if (!profile->hash)
		goto fail;

	desc.shash.tfm = pyronia_tfm;
	desc.shash.flags = 0;

	error = crypto_shash_init(&desc.shash);
	if (error)
		goto fail;
	error = crypto_shash_update(&desc.shash, (u8 *) &le32_version, 4);
	if (error)
		goto fail;
	error = crypto_shash_update(&desc.shash, (u8 *) start, len);
	if (error)
		goto fail;
	error = crypto_shash_final(&desc.shash, profile->hash);
	if (error)
		goto fail;

	return 0;

fail:
	kfree(profile->hash);
	profile->hash = NULL;

	return error;
}

static int __init init_profile_hash(void)
{
	struct crypto_shash *tfm;

	if (!pyronia_initialized)
		return 0;

	tfm = crypto_alloc_shash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		int error = PTR_ERR(tfm);
		PYR_ERROR("failed to setup profile sha1 hashing: %d\n", error);
		return error;
	}
	pyronia_tfm = tfm;
	pyronia_hash_size = crypto_shash_digestsize(pyronia_tfm);

	pyr_info_message("Pyronia sha1 policy hashing enabled");

	return 0;
}

late_initcall(init_profile_hash);