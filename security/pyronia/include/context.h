/*
 * AppArmor security module
 *
 * This file contains AppArmor contexts used to associate "labels" to objects.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_CONTEXT_H
#define __PYR_CONTEXT_H

#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "policy.h"

#define cred_cxt(X) (X)->security
#define current_cxt() cred_cxt(current_cred())

/* struct pyr_file_cxt - the AppArmor context the file was opened in
 * @perms: the permission the file was opened with
 *
 * The file_cxt could currently be directly stored in file->f_security
 * as the profile reference is now stored in the f_cred.  However the
 * cxt struct will expand in the future so we keep the struct.
 */
struct pyr_file_cxt {
	u16 allow;
};

/**
 * pyr_alloc_file_context - allocate file_cxt
 * @gfp: gfp flags for allocation
 *
 * Returns: file_cxt or NULL on failure
 */
static inline struct pyr_file_cxt *pyr_alloc_file_context(gfp_t gfp)
{
	return kzalloc(sizeof(struct pyr_file_cxt), gfp);
}

/**
 * pyr_free_file_context - free a file_cxt
 * @cxt: file_cxt to free  (MAYBE_NULL)
 */
static inline void pyr_free_file_context(struct pyr_file_cxt *cxt)
{
	if (cxt)
		kzfree(cxt);
}

/**
 * struct pyr_task_cxt - primary label for confined tasks
 * @profile: the current profile   (NOT NULL)
 * @exec: profile to transition to on next exec  (MAYBE NULL)
 * @previous: profile the task may return to     (MAYBE NULL)
 * @token: magic value the task must know for returning to @previous_profile
 *
 * Contains the task's current profile (which could change due to
 * change_hat).  Plus the hat_magic needed during change_hat.
 *
 * TODO: make so a task can be confined by a stack of contexts
 */
struct pyr_task_cxt {
	struct pyr_profile *profile;
	struct pyr_profile *onexec;
	struct pyr_profile *previous;
	u64 token;
};

struct pyr_task_cxt *pyr_alloc_task_context(gfp_t flags);
void pyr_free_task_context(struct pyr_task_cxt *cxt);
void pyr_dup_task_context(struct pyr_task_cxt *new,
			 const struct pyr_task_cxt *old);
int pyr_replace_current_profile(struct pyr_profile *profile);
int pyr_set_current_onexec(struct pyr_profile *profile);
int pyr_set_current_hat(struct pyr_profile *profile, u64 token);
int pyr_restore_previous_profile(u64 cookie);
struct pyr_profile *pyr_get_task_profile(struct task_struct *task);


/**
 * pyr_cred_profile - obtain cred's profiles
 * @cred: cred to obtain profiles from  (NOT NULL)
 *
 * Returns: confining profile
 *
 * does NOT increment reference count
 */
static inline struct pyr_profile *pyr_cred_profile(const struct cred *cred)
{
	struct pyr_task_cxt *cxt = cred_cxt(cred);
	BUG_ON(!cxt || !cxt->profile);
	return cxt->profile;
}

/**
 * __pyr_task_profile - retrieve another task's profile
 * @task: task to query  (NOT NULL)
 *
 * Returns: @task's profile without incrementing its ref count
 *
 * If @task != current needs to be called in RCU safe critical section
 */
static inline struct pyr_profile *__pyr_task_profile(struct task_struct *task)
{
	return pyr_cred_profile(__task_cred(task));
}

/**
 * __pyr_task_is_confined - determine if @task has any confinement
 * @task: task to check confinement of  (NOT NULL)
 *
 * If @task != current needs to be called in RCU safe critical section
 */
static inline bool __pyr_task_is_confined(struct task_struct *task)
{
	return !unconfined(__pyr_task_profile(task));
}

/**
 * __pyr_current_profile - find the current tasks confining profile
 *
 * Returns: up to date confining profile or the ns unconfined profile (NOT NULL)
 *
 * This fn will not update the tasks cred to the most up to date version
 * of the profile so it is safe to call when inside of locks.
 */
static inline struct pyr_profile *__pyr_current_profile(void)
{
	return pyr_cred_profile(current_cred());
}

/**
 * pyr_current_profile - find the current tasks confining profile and do updates
 *
 * Returns: up to date confining profile or the ns unconfined profile (NOT NULL)
 *
 * This fn will update the tasks cred structure if the profile has been
 * replaced.  Not safe to call inside locks
 */
static inline struct pyr_profile *pyr_current_profile(void)
{
	const struct pyr_task_cxt *cxt = current_cxt();
	struct pyr_profile *profile;
	BUG_ON(!cxt || !cxt->profile);

	if (PROFILE_INVALID(cxt->profile)) {
		profile = pyr_get_newest_profile(cxt->profile);
		pyr_replace_current_profile(profile);
		pyr_put_profile(profile);
		cxt = current_cxt();
	}

	return cxt->profile;
}

/**
 * pyr_clear_task_cxt_trans - clear transition tracking info from the cxt
 * @cxt: task context to clear (NOT NULL)
 */
static inline void pyr_clear_task_cxt_trans(struct pyr_task_cxt *cxt)
{
	pyr_put_profile(cxt->previous);
	pyr_put_profile(cxt->onexec);
	cxt->previous = NULL;
	cxt->onexec = NULL;
	cxt->token = 0;
}

#endif /* __PYR_CONTEXT_H */
