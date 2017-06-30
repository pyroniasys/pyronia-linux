/*
 * AppArmor security module
 *
 * This file contains AppArmor auditing function definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_AUDIT_H
#define __PYR_AUDIT_H

#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/lsm_audit.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "file.h"

struct pyr_profile;

extern const char *const pyr_audit_mode_names[];
#define AUDIT_MAX_INDEX 5
enum audit_mode {
	AUDIT_NORMAL,		/* follow normal auditing of accesses */
	AUDIT_QUIET_DENIED,	/* quiet all denied access messages */
	AUDIT_QUIET,		/* quiet all messages */
	AUDIT_NOQUIET,		/* do not quiet audit messages */
	AUDIT_ALL		/* audit all accesses */
};

enum audit_type {
	AUDIT_PYRONIA_AUDIT,
	AUDIT_PYRONIA_ALLOWED,
	AUDIT_PYRONIA_DENIED,
	AUDIT_PYRONIA_HINT,
	AUDIT_PYRONIA_STATUS,
	AUDIT_PYRONIA_ERROR,
	AUDIT_PYRONIA_KILL,
	AUDIT_PYRONIA_AUTO
};

extern const char *const pyr_op_table[];
enum pyr_ops {
	OP_NULL,

	OP_SYSCTL,
	OP_CAPABLE,

	OP_UNLINK,
	OP_MKDIR,
	OP_RMDIR,
	OP_MKNOD,
	OP_TRUNC,
	OP_LINK,
	OP_SYMLINK,
	OP_RENAME_SRC,
	OP_RENAME_DEST,
	OP_CHMOD,
	OP_CHOWN,
	OP_GETATTR,
	OP_OPEN,

	OP_FPERM,
	OP_FLOCK,
	OP_FMMAP,
	OP_FMPROT,

	OP_PIVOTROOT,
	OP_MOUNT,
	OP_UMOUNT,

	OP_CREATE,
	OP_POST_CREATE,
	OP_BIND,
	OP_CONNECT,
	OP_LISTEN,
	OP_ACCEPT,
	OP_SENDMSG,
	OP_RECVMSG,
	OP_GETSOCKNAME,
	OP_GETPEERNAME,
	OP_GETSOCKOPT,
	OP_SETSOCKOPT,
	OP_SOCK_SHUTDOWN,

	OP_PTRACE,

	OP_EXEC,
	OP_CHANGE_HAT,
	OP_CHANGE_PROFILE,
	OP_CHANGE_ONEXEC,

	OP_SETPROCATTR,
	OP_SETRLIMIT,

	OP_PROF_REPL,
	OP_PROF_LOAD,
	OP_PROF_RM,
};


struct pyronia_audit_data {
	int error;
	int op;
	int type;
	void *profile;
	const char *name;
	const char *info;
	union {
		void *target;
		struct {
			long pos;
			void *target;
		} iface;
		struct {
			int rlim;
			unsigned long max;
		} rlim;
		struct {
			const char *src_name;
			const char *type;
			const char *trans;
			const char *data;
			unsigned long flags;
		} mnt;
		struct {
			const char *target;
			u32 request;
			u32 denied;
			kuid_t ouid;
		} fs;
		struct {
			int type, protocol;
			struct sock *sk;
		} net;
	};
};

/* define a short hand for pyronia_audit_data structure */
#define pyrd pyronia_audit_data

void pyr_audit_msg(int type, struct common_audit_data *sa,
		  void (*cb) (struct audit_buffer *, void *));
int pyr_audit(int type, struct pyr_profile *profile, gfp_t gfp,
	     struct common_audit_data *sa,
	     void (*cb) (struct audit_buffer *, void *));

static inline int complain_error(int error)
{
	if (error == -EPERM || error == -EACCES)
		return 0;
	return error;
}

#endif /* __PYR_AUDIT_H */
