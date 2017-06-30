/*
 * AppArmor security module
 *
 * This file contains AppArmor security domain transition function definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/binfmts.h>
#include <linux/types.h>

#ifndef __PYR_DOMAIN_H
#define __PYR_DOMAIN_H

struct pyr_domain {
	int size;
	char **table;
};

struct pyr_profile *pyr_x_table_lookup(struct pyr_profile *profile, u32 xindex);

int pyronia_bprm_set_creds(struct linux_binprm *bprm);
int pyronia_bprm_secureexec(struct linux_binprm *bprm);
void pyronia_bprm_committing_creds(struct linux_binprm *bprm);
void pyronia_bprm_committed_creds(struct linux_binprm *bprm);

void pyr_free_domain_entries(struct pyr_domain *domain);
int pyr_change_hat(const char *hats[], int count, u64 token, bool permtest);
int pyr_change_profile(const char *ns_name, const char *name, bool onexec,
		      bool permtest);

#endif /* __PYR_DOMAIN_H */
