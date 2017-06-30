/*
 * AppArmor security module
 *
 * This file contains AppArmor ipc mediation
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/gfp.h>
#include <linux/ptrace.h>

#include "include/audit.h"
#include "include/capability.h"
#include "include/context.h"
#include "include/policy.h"
#include "include/ipc.h"

/* call back to audit ptrace fields */
static void audit_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;
	audit_log_format(ab, " target=");
	audit_log_untrustedstring(ab, sa->pyrd->target);
}

/**
 * pyr_audit_ptrace - do auditing for ptrace
 * @profile: profile being enforced  (NOT NULL)
 * @target: profile being traced (NOT NULL)
 * @error: error condition
 *
 * Returns: %0 or error code
 */
static int pyr_audit_ptrace(struct pyr_profile *profile,
			   struct pyr_profile *target, int error)
{
	struct common_audit_data sa;
	struct pyronia_audit_data pyrd = {0,};
	sa.type = LSM_AUDIT_DATA_NONE;
	sa.pyrd = &pyrd;
	pyrd.op = OP_PTRACE;
	pyrd.target = target;
	pyrd.error = error;

	return pyr_audit(AUDIT_PYRONIA_AUTO, profile, GFP_ATOMIC, &sa,
			audit_cb);
}

/**
 * pyr_may_ptrace - test if tracer task can trace the tracee
 * @tracer: profile of the task doing the tracing  (NOT NULL)
 * @tracee: task to be traced
 * @mode: whether PTRACE_MODE_READ || PTRACE_MODE_ATTACH
 *
 * Returns: %0 else error code if permission denied or error
 */
int pyr_may_ptrace(struct pyr_profile *tracer, struct pyr_profile *tracee,
		  unsigned int mode)
{
	/* TODO: currently only based on capability, not extended ptrace
	 *       rules,
	 *       Test mode for PTRACE_MODE_READ || PTRACE_MODE_ATTACH
	 */

	if (unconfined(tracer) || tracer == tracee)
		return 0;
	/* log this capability request */
	return pyr_capable(tracer, CAP_SYS_PTRACE, 1);
}

/**
 * pyr_ptrace - do ptrace permission check and auditing
 * @tracer: task doing the tracing (NOT NULL)
 * @tracee: task being traced (NOT NULL)
 * @mode: ptrace mode either PTRACE_MODE_READ || PTRACE_MODE_ATTACH
 *
 * Returns: %0 else error code if permission denied or error
 */
int pyr_ptrace(struct task_struct *tracer, struct task_struct *tracee,
	      unsigned int mode)
{
	/*
	 * tracer can ptrace tracee when
	 * - tracer is unconfined ||
	 *   - tracer is in complain mode
	 *   - tracer has rules allowing it to trace tracee currently this is:
	 *       - confined by the same profile ||
	 *       - tracer profile has CAP_SYS_PTRACE
	 */

	struct pyr_profile *tracer_p = pyr_get_task_profile(tracer);
	int error = 0;

	if (!unconfined(tracer_p)) {
		struct pyr_profile *tracee_p = pyr_get_task_profile(tracee);

		error = pyr_may_ptrace(tracer_p, tracee_p, mode);
		error = pyr_audit_ptrace(tracer_p, tracee_p, error);

		pyr_put_profile(tracee_p);
	}
	pyr_put_profile(tracer_p);

	return error;
}
