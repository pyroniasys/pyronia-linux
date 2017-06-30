/*
 * AppArmor security module
 *
 * This file contains AppArmor security identifier (sid) definitions
 *
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_SID_H
#define __PYR_SID_H

#include <linux/types.h>

/* sid value that will not be allocated */
#define PYR_SID_INVALID 0
#define PYR_SID_ALLOC PYR_SID_INVALID

u32 pyr_alloc_sid(void);
void pyr_free_sid(u32 sid);

#endif /* __PYR_SID_H */
