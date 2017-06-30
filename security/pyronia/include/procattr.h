/*
 * AppArmor security module
 *
 * This file contains AppArmor /proc/<pid>/attr/ interface function definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_PROCATTR_H
#define __PYR_PROCATTR_H

#define PYR_DO_TEST 1
#define PYR_ONEXEC  1

int pyr_getprocattr(struct pyr_profile *profile, char **string);
int pyr_setprocattr_changehat(char *args, size_t size, int test);
int pyr_setprocattr_changeprofile(char *fqname, bool onexec, int test);

#endif /* __PYR_PROCATTR_H */
