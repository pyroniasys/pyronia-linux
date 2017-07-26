/*
 * Pyronia security module
 *
 * This file contains Pyronia capability mediation definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2013 Canonical Ltd.
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_CAPABILITY_H
#define __PYR_CAPABILITY_H

#include <linux/sched.h>

#include "pyroniafs.h"

struct pyr_profile;

/* pyr_caps - confinement data for capabilities
 * @allowed: capabilities mask
 * @audit: caps that are to be audited
 * @quiet: caps that should not be audited
 * @kill: caps that when requested will result in the task being killed
 * @extended: caps that are subject finer grained mediation
 */
struct pyr_caps {
	kernel_cap_t allow;
	kernel_cap_t audit;
	kernel_cap_t quiet;
	kernel_cap_t kill;
	kernel_cap_t extended;
};

extern struct pyr_fs_entry pyr_fs_entry_caps[];

int pyr_capable(struct pyr_profile *profile, int cap, int audit);

static inline void pyr_free_cap_rules(struct pyr_caps *caps)
{
	/* NOP */
}

#endif /* __PYR_CAPBILITY_H */
