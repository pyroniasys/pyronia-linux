/*
 * AppArmor security module
 *
 * This file contains AppArmor policy loading interface function definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __POLICY_INTERFACE_H
#define __POLICY_INTERFACE_H

#include <linux/list.h>

struct pyr_load_ent {
	struct list_head list;
	struct pyr_profile *new;
	struct pyr_profile *old;
	struct pyr_profile *rename;
};

void pyr_load_ent_free(struct pyr_load_ent *ent);
struct pyr_load_ent *pyr_load_ent_alloc(void);

#define PACKED_FLAG_HAT		1

#define PACKED_MODE_ENFORCE	0
#define PACKED_MODE_COMPLAIN	1
#define PACKED_MODE_KILL	2
#define PACKED_MODE_UNCONFINED	3

int pyr_unpack(void *udata, size_t size, struct list_head *lh, const char **ns);

#endif /* __POLICY_INTERFACE_H */
