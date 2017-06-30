/*
 * AppArmor security module
 *
 * This file contains AppArmor resource mediation and attachment
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/audit.h>

#include "include/audit.h"
#include "include/context.h"
#include "include/resource.h"
#include "include/policy.h"

/*
 * Table of rlimit names: we generate it from resource.h.
 */
#include "rlim_names.h"

struct pyr_fs_entry pyr_fs_entry_rlimit[] = {
	PYR_FS_FILE_STRING("mask", PYR_FS_RLIMIT_MASK),
	{ }
};

/* audit callback for resource specific fields */
static void audit_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	audit_log_format(ab, " rlimit=%s value=%lu",
			 rlim_names[sa->pyrd->rlim.rlim], sa->pyrd->rlim.max);
}

/**
 * audit_resource - audit setting resource limit
 * @profile: profile being enforced  (NOT NULL)
 * @resoure: rlimit being auditing
 * @value: value being set
 * @error: error value
 *
 * Returns: 0 or sa->error else other error code on failure
 */
static int audit_resource(struct pyr_profile *profile, unsigned int resource,
			  unsigned long value, int error)
{
	struct common_audit_data sa;
	struct pyronia_audit_data pyrd = {0,};

	sa.type = LSM_AUDIT_DATA_NONE;
	sa.pyrd = &pyrd;
	pyrd.op = OP_SETRLIMIT,
	pyrd.rlim.rlim = resource;
	pyrd.rlim.max = value;
	pyrd.error = error;
	return pyr_audit(AUDIT_PYRONIA_AUTO, profile, GFP_KERNEL, &sa,
			audit_cb);
}

/**
 * pyr_map_resouce - map compiled policy resource to internal #
 * @resource: flattened policy resource number
 *
 * Returns: resource # for the current architecture.
 *
 * rlimit resource can vary based on architecture, map the compiled policy
 * resource # to the internal representation for the architecture.
 */
int pyr_map_resource(int resource)
{
	return rlim_map[resource];
}

/**
 * pyr_task_setrlimit - test permission to set an rlimit
 * @profile - profile confining the task  (NOT NULL)
 * @task - task the resource is being set on
 * @resource - the resource being set
 * @new_rlim - the new resource limit  (NOT NULL)
 *
 * Control raising the processes hard limit.
 *
 * Returns: 0 or error code if setting resource failed
 */
int pyr_task_setrlimit(struct pyr_profile *profile, struct task_struct *task,
		      unsigned int resource, struct rlimit *new_rlim)
{
	struct pyr_profile *task_profile;
	int error = 0;

	rcu_read_lock();
	task_profile = pyr_get_profile(pyr_cred_profile(__task_cred(task)));
	rcu_read_unlock();

	/* TODO: extend resource control to handle other (non current)
	 * profiles.  AppArmor rules currently have the implicit assumption
	 * that the task is setting the resource of a task confined with
	 * the same profile or that the task setting the resource of another
	 * task has CAP_SYS_RESOURCE.
	 */
	if ((profile != task_profile &&
	     pyr_capable(profile, CAP_SYS_RESOURCE, 1)) ||
	    (profile->rlimits.mask & (1 << resource) &&
	     new_rlim->rlim_max > profile->rlimits.limits[resource].rlim_max))
		error = -EACCES;

	pyr_put_profile(task_profile);

	return audit_resource(profile, resource, new_rlim->rlim_max, error);
}

/**
 * __pyr_transition_rlimits - apply new profile rlimits
 * @old: old profile on task  (NOT NULL)
 * @new: new profile with rlimits to apply  (NOT NULL)
 */
void __pyr_transition_rlimits(struct pyr_profile *old, struct pyr_profile *new)
{
	unsigned int mask = 0;
	struct rlimit *rlim, *initrlim;
	int i;

	/* for any rlimits the profile controlled reset the soft limit
	 * to the less of the tasks hard limit and the init tasks soft limit
	 */
	if (old->rlimits.mask) {
		for (i = 0, mask = 1; i < RLIM_NLIMITS; i++, mask <<= 1) {
			if (old->rlimits.mask & mask) {
				rlim = current->signal->rlim + i;
				initrlim = init_task.signal->rlim + i;
				rlim->rlim_cur = min(rlim->rlim_max,
						     initrlim->rlim_cur);
			}
		}
	}

	/* set any new hard limits as dictated by the new profile */
	if (!new->rlimits.mask)
		return;
	for (i = 0, mask = 1; i < RLIM_NLIMITS; i++, mask <<= 1) {
		if (!(new->rlimits.mask & mask))
			continue;

		rlim = current->signal->rlim + i;
		rlim->rlim_max = min(rlim->rlim_max,
				     new->rlimits.limits[i].rlim_max);
		/* soft limit should not exceed hard limit */
		rlim->rlim_cur = min(rlim->rlim_cur, rlim->rlim_max);
	}
}
