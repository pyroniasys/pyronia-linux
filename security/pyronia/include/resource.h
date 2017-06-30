/*
 * AppArmor security module
 *
 * This file contains AppArmor resource limits function definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_RESOURCE_H
#define __PYR_RESOURCE_H

#include <linux/resource.h>
#include <linux/sched.h>

#include "pyroniafs.h"

struct pyr_profile;

/* struct pyr_rlimit - rlimit settings for the profile
 * @mask: which hard limits to set
 * @limits: rlimit values that override task limits
 *
 * AppArmor rlimits are used to set confined task rlimits.  Only the
 * limits specified in @mask will be controlled by pyronia.
 */
struct pyr_rlimit {
	unsigned int mask;
	struct rlimit limits[RLIM_NLIMITS];
};

extern struct pyr_fs_entry pyr_fs_entry_rlimit[];

int pyr_map_resource(int resource);
int pyr_task_setrlimit(struct pyr_profile *profile, struct task_struct *,
		      unsigned int resource, struct rlimit *new_rlim);

void __pyr_transition_rlimits(struct pyr_profile *old, struct pyr_profile *new);

static inline void pyr_free_rlimit_rules(struct pyr_rlimit *rlims)
{
	/* NOP */
}

#endif /* __PYR_RESOURCE_H */
