/*
 * AppArmor security module
 *
 * This file contains AppArmor ipc mediation function definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_IPC_H
#define __PYR_IPC_H

#include <linux/sched.h>

struct pyr_profile;

int pyr_may_ptrace(struct pyr_profile *tracer, struct pyr_profile *tracee,
		  unsigned int mode);

int pyr_ptrace(struct task_struct *tracer, struct task_struct *tracee,
	      unsigned int mode);

#endif /* __PYR_IPC_H */
