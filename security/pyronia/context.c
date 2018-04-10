/*
 * AppArmor security module
 *
 * This file contains AppArmor functions used to manipulate object security
 * contexts.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 *
 * AppArmor sets confinement on every task, via the the pyr_task_cxt and
 * the pyr_task_cxt.profile, both of which are required and are not allowed
 * to be NULL.  The pyr_task_cxt is not reference counted and is unique
 * to each cred (which is reference count).  The profile pointed to by
 * the task_cxt is reference counted.
 *
 * TODO
 * If a task uses change_hat it currently does not return to the old
 * cred or task context but instead creates a new one.  Ideally the task
 * should return to the previous cred if it has not been modified.
 *
 */

#include "include/context.h"
#include "include/policy.h"

/**
 * pyr_alloc_task_context - allocate a new task_cxt
 * @flags: gfp flags for allocation
 *
 * Returns: allocated buffer or NULL on failure
 */
struct pyr_task_cxt *pyr_alloc_task_context(gfp_t flags)
{
	return kzalloc(sizeof(struct pyr_task_cxt), flags);
}

/**
 * pyr_free_task_context - free a task_cxt
 * @cxt: task_cxt to free (MAYBE NULL)
 */
void pyr_free_task_context(struct pyr_task_cxt *cxt)
{
	if (cxt) {
	  pyr_put_profile(cxt->profile);
	  pyr_put_profile(cxt->previous);
	  pyr_put_profile(cxt->onexec);
	  
	  kzfree(cxt);
	}
}

/**
 * pyr_dup_task_context - duplicate a task context, incrementing reference counts
 * @new: a blank task context      (NOT NULL)
 * @old: the task context to copy  (NOT NULL)
 */
void pyr_dup_task_context(struct pyr_task_cxt *new, const struct pyr_task_cxt *old)
{
	*new = *old;
	pyr_get_profile(new->profile);
	pyr_get_profile(new->previous);
	pyr_get_profile(new->onexec);
}

/**
 * pyr_get_task_profile - Get another task's profile
 * @task: task to query  (NOT NULL)
 *
 * Returns: counted reference to @task's profile
 */
struct pyr_profile *pyr_get_task_profile(struct task_struct *task)
{
	struct pyr_profile *p;

	rcu_read_lock();
	p = pyr_get_profile(__pyr_task_profile(task));
	rcu_read_unlock();

	return p;
}

/**
 * pyr_replace_current_profile - replace the current tasks profiles
 * @profile: new profile  (NOT NULL)
 *
 * Returns: 0 or error on failure
 */
int pyr_replace_current_profile(struct pyr_profile *profile)
{
	struct pyr_task_cxt *cxt = current_cxt();
	struct cred *new;
	BUG_ON(!profile);
	
	if (cxt->profile == profile)
		return 0;

	new  = prepare_creds();
	if (!new)
		return -ENOMEM;

	cxt = cred_cxt(new);
	if (unconfined(profile) || (cxt->profile->ns != profile->ns))
		/* if switching to unconfined or a different profile namespace
		 * clear out context state
		 */
		pyr_clear_task_cxt_trans(cxt);

	/* be careful switching cxt->profile, when racing replacement it
	 * is possible that cxt->profile->replacedby->profile is the reference
	 * keeping @profile valid, so make sure to get its reference before
	 * dropping the reference on cxt->profile */
	pyr_get_profile(profile);
	pyr_put_profile(cxt->profile);
	cxt->profile = profile;

	commit_creds(new);
	return 0;
}

/**
 * pyr_set_current_onexec - set the tasks change_profile to happen onexec
 * @profile: system profile to set at exec  (MAYBE NULL to clear value)
 *
 * Returns: 0 or error on failure
 */
int pyr_set_current_onexec(struct pyr_profile *profile)
{
	struct pyr_task_cxt *cxt;
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;
	
	cxt = cred_cxt(new);
	pyr_get_profile(profile);
	pyr_put_profile(cxt->onexec);
	cxt->onexec = profile;

	commit_creds(new);
	return 0;
}

/**
 * pyr_set_current_hat - set the current tasks hat
 * @profile: profile to set as the current hat  (NOT NULL)
 * @token: token value that must be specified to change from the hat
 *
 * Do switch of tasks hat.  If the task is currently in a hat
 * validate the token to match.
 *
 * Returns: 0 or error on failure
 */
int pyr_set_current_hat(struct pyr_profile *profile, u64 token)
{
	struct pyr_task_cxt *cxt;
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;
	BUG_ON(!profile);

	PYR_DEBUG("[%s] got here: lib perm defaults: %p\n", __func__, profile->lib_perm_db->defaults);
	
	cxt = cred_cxt(new);
	if (!cxt->previous) {
		/* transfer refcount */
		cxt->previous = cxt->profile;
		cxt->token = token;
	} else if (cxt->token == token) {
		pyr_put_profile(cxt->profile);
	} else {
		/* previous_profile && cxt->token != token */
		abort_creds(new);
		return -EACCES;
	}
	cxt->profile = pyr_get_newest_profile(profile);
	/* clear exec on switching context */
	pyr_put_profile(cxt->onexec);
	cxt->onexec = NULL;

	commit_creds(new);
	return 0;
}

/**
 * pyr_restore_previous_profile - exit from hat context restoring the profile
 * @token: the token that must be matched to exit hat context
 *
 * Attempt to return out of a hat to the previous profile.  The token
 * must match the stored token value.
 *
 * Returns: 0 or error of failure
 */
int pyr_restore_previous_profile(u64 token)
{
	struct pyr_task_cxt *cxt;
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;
	
	cxt = cred_cxt(new);
	if (cxt->token != token) {
		abort_creds(new);
		return -EACCES;
	}
	/* ignore restores when there is no saved profile */
	if (!cxt->previous) {
		abort_creds(new);
		return 0;
	}
	PYR_DEBUG("[%s] got here: lib perm defaults: %p\n", __func__, cxt->profile->lib_perm_db->defaults);

	pyr_put_profile(cxt->profile);
	cxt->profile = pyr_get_newest_profile(cxt->previous);
	BUG_ON(!cxt->profile);
	/* clear exec && prev information when restoring to previous context */
	pyr_clear_task_cxt_trans(cxt);

	commit_creds(new);
	return 0;
}
