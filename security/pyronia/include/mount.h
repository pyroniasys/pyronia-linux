/*
 * AppArmor security module
 *
 * This file contains AppArmor file mediation function definitions.
 *
 * Copyright 2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_MOUNT_H
#define __PYR_MOUNT_H

#include <linux/fs.h>
#include <linux/path.h>

#include "domain.h"
#include "policy.h"

/* mount perms */
#define PYR_MAY_PIVOTROOT	0x01
#define PYR_MAY_MOUNT		0x02
#define PYR_MAY_UMOUNT		0x04
#define PYR_AUDIT_DATA		0x40
#define PYR_CONT_MATCH		0x40

#define PYR_MS_IGNORE_MASK (MS_KERNMOUNT | MS_NOSEC | MS_ACTIVE | MS_BORN)

int pyr_remount(struct pyr_profile *profile, const struct path *path,
	       unsigned long flags, void *data);

int pyr_bind_mount(struct pyr_profile *profile, const struct path *path,
		  const char *old_name, unsigned long flags);


int pyr_mount_change_type(struct pyr_profile *profile, const struct path *path,
			 unsigned long flags);

int pyr_move_mount(struct pyr_profile *profile, const struct path *path,
		  const char *old_name);

int pyr_new_mount(struct pyr_profile *profile, const char *dev_name,
		 const struct path *path, const char *type, unsigned long flags,
		 void *data);

int pyr_umount(struct pyr_profile *profile, struct vfsmount *mnt, int flags);

int pyr_pivotroot(struct pyr_profile *profile, const struct path *old_path,
		 const struct path *new_path);

#endif /* __PYR_MOUNT_H */
