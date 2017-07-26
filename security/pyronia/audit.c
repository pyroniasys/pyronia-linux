/*
 * Pyronia security module
 *
 * This file contains Pyronia auditing functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/audit.h>
#include <linux/socket.h>

#include "include/pyronia.h"
#include "include/audit.h"
#include "include/policy.h"

const char *const pyr_op_table[] = {
	"null",

	"sysctl",
	"capable",

	"unlink",
	"mkdir",
	"rmdir",
	"mknod",
	"truncate",
	"link",
	"symlink",
	"rename_src",
	"rename_dest",
	"chmod",
	"chown",
	"getattr",
	"open",

	"file_perm",
	"file_lock",
	"file_mmap",
	"file_mprotect",

	"pivotroot",
	"mount",
	"umount",

	"create",
	"post_create",
	"bind",
	"connect",
	"listen",
	"accept",
	"sendmsg",
	"recvmsg",
	"getsockname",
	"getpeername",
	"getsockopt",
	"setsockopt",
	"socket_shutdown",

	"ptrace",

	"exec",
	"change_hat",
	"change_profile",
	"change_onexec",

	"setprocattr",
	"setrlimit",

	"profile_replace",
	"profile_load",
	"profile_remove"
};

const char *const pyr_audit_mode_names[] = {
	"normal",
	"quiet_denied",
	"quiet",
	"noquiet",
	"all"
};

static const char *const pyr_audit_type[] = {
	"AUDIT",
	"ALLOWED",
	"DENIED",
	"HINT",
	"STATUS",
	"ERROR",
	"KILLED",
	"AUTO"
};

/*
 * Currently Pyronia auditing is fed straight into the audit framework.
 *
 * TODO:
 * netlink interface for complain mode
 * user auditing, - send user auditing to netlink interface
 * system control of whether user audit messages go to system log
 */

/**
 * audit_base - core Pyronia function.
 * @ab: audit buffer to fill (NOT NULL)
 * @ca: audit structure containing data to audit (NOT NULL)
 *
 * Record common Pyronia audit data from @sa
 */
static void audit_pre(struct audit_buffer *ab, void *ca)
{
	struct common_audit_data *sa = ca;

	if (pyr_g_audit_header) {
		audit_log_format(ab, "pyronia=");
		audit_log_string(ab, pyr_audit_type[sa->pyrd->type]);
	}

	if (sa->pyrd->op) {
		audit_log_format(ab, " operation=");
		audit_log_string(ab, pyr_op_table[sa->pyrd->op]);
	}

	if (sa->pyrd->info) {
		audit_log_format(ab, " info=");
		audit_log_string(ab, sa->pyrd->info);
		if (sa->pyrd->error)
			audit_log_format(ab, " error=%d", sa->pyrd->error);
	}

	if (sa->pyrd->profile) {
		struct pyr_profile *profile = sa->pyrd->profile;
		if (profile->ns != pyr_root_ns) {
			audit_log_format(ab, " namespace=");
			audit_log_untrustedstring(ab, profile->ns->base.hname);
		}
		audit_log_format(ab, " profile=");
		audit_log_untrustedstring(ab, profile->base.hname);
	}

	if (sa->pyrd->name) {
		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, sa->pyrd->name);
	}
}

/**
 * pyr_audit_msg - Log a message to the audit subsystem
 * @sa: audit event structure (NOT NULL)
 * @cb: optional callback fn for type specific fields (MAYBE NULL)
 */
void pyr_audit_msg(int type, struct common_audit_data *sa,
		  void (*cb) (struct audit_buffer *, void *))
{
	sa->pyrd->type = type;
	common_lsm_audit(sa, audit_pre, cb);
}

/**
 * pyr_audit - Log a profile based audit event to the audit subsystem
 * @type: audit type for the message
 * @profile: profile to check against (NOT NULL)
 * @gfp: allocation flags to use
 * @sa: audit event (NOT NULL)
 * @cb: optional callback fn for type specific fields (MAYBE NULL)
 *
 * Handle default message switching based off of audit mode flags
 *
 * Returns: error on failure
 */
int pyr_audit(int type, struct pyr_profile *profile, gfp_t gfp,
	     struct common_audit_data *sa,
	     void (*cb) (struct audit_buffer *, void *))
{
	BUG_ON(!profile);

	if (type == AUDIT_PYRONIA_AUTO) {
		if (likely(!sa->pyrd->error)) {
			if (AUDIT_MODE(profile) != AUDIT_ALL)
				return 0;
			type = AUDIT_PYRONIA_AUDIT;
		} else if (COMPLAIN_MODE(profile))
			type = AUDIT_PYRONIA_ALLOWED;
		else
			type = AUDIT_PYRONIA_DENIED;
	}
	if (AUDIT_MODE(profile) == AUDIT_QUIET ||
	    (type == AUDIT_PYRONIA_DENIED &&
	     AUDIT_MODE(profile) == AUDIT_QUIET))
		return sa->pyrd->error;

	if (KILL_MODE(profile) && type == AUDIT_PYRONIA_DENIED)
		type = AUDIT_PYRONIA_KILL;

	if (!unconfined(profile))
		sa->pyrd->profile = profile;

	pyr_audit_msg(type, sa, cb);

	if (sa->pyrd->type == AUDIT_PYRONIA_KILL)
		(void)send_sig_info(SIGKILL, NULL,
			sa->type == LSM_AUDIT_DATA_TASK && sa->u.tsk ?
				    sa->u.tsk : current);

	if (sa->pyrd->type == AUDIT_PYRONIA_ALLOWED)
		return complain_error(sa->pyrd->error);

	return sa->pyrd->error;
}
