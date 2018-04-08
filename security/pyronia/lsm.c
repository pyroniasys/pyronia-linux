/*
 * AppArmor security module
 *
 * This file contains AppArmor LSM hooks.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/lsm_hooks.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/ctype.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/user_namespace.h>
#include <net/sock.h>

#include "include/pyronia.h"
#include "include/pyroniafs.h"
#include "include/audit.h"
#include "include/capability.h"
#include "include/context.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/net.h"
#include "include/path.h"
#include "include/policy.h"
#include "include/procattr.h"
#include "include/mount.h"

/* Flag indicating whether initialization completed */
int pyronia_initialized __initdata;

/*
 * LSM hook functions
 */

/*
 * free the associated pyr_task_cxt and put its profiles
 */
static void pyronia_cred_free(struct cred *cred)
{
	pyr_free_task_context(cred_cxt(cred));
	cred_cxt(cred) = NULL;
}

/*
 * allocate the pyronia part of blank credentials
 */
static int pyronia_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/* freed by pyronia_cred_free */
	struct pyr_task_cxt *cxt = pyr_alloc_task_context(gfp);
	if (!cxt)
		return -ENOMEM;

	cred_cxt(cred) = cxt;
	return 0;
}

/*
 * prepare new pyr_task_cxt for modification by prepare_cred block
 */
static int pyronia_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	/* freed by pyronia_cred_free */
	struct pyr_task_cxt *cxt = pyr_alloc_task_context(gfp);
	if (!cxt)
		return -ENOMEM;

	pyr_dup_task_context(cxt, cred_cxt(old));
	cred_cxt(new) = cxt;
	return 0;
}

/*
 * transfer the pyronia data to a blank set of creds
 */
static void pyronia_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct pyr_task_cxt *old_cxt = cred_cxt(old);
	struct pyr_task_cxt *new_cxt = cred_cxt(new);

	pyr_dup_task_context(new_cxt, old_cxt);
}

static int pyronia_ptrace_access_check(struct task_struct *child,
					unsigned int mode)
{
	return pyr_ptrace(current, child, mode);
}

static int pyronia_ptrace_traceme(struct task_struct *parent)
{
	return pyr_ptrace(parent, current, PTRACE_MODE_ATTACH);
}

/* Derived from security/commoncap.c:cap_capget */
static int pyronia_capget(struct task_struct *target, kernel_cap_t *effective,
			   kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	struct pyr_profile *profile;
	const struct cred *cred;

	rcu_read_lock();
	cred = __task_cred(target);
	profile = pyr_cred_profile(cred);

	/*
	 * cap_capget is stacked ahead of this and will
	 * initialize effective and permitted.
	 */
	if (!unconfined(profile) && !COMPLAIN_MODE(profile)) {
		*effective = cap_intersect(*effective, profile->caps.allow);
		*permitted = cap_intersect(*permitted, profile->caps.allow);
	}
	rcu_read_unlock();

	return 0;
}

static int pyronia_capable(const struct cred *cred, struct user_namespace *ns,
			    int cap, int audit)
{
	struct pyr_profile *profile;
	int error = 0;

	profile = pyr_cred_profile(cred);
	if (!unconfined(profile))
		error = pyr_capable(profile, cap, audit);
	return error;
}

/**
 * common_perm - basic common permission check wrapper fn for paths
 * @op: operation being checked
 * @path: path to check permission of  (NOT NULL)
 * @mask: requested permissions mask
 * @cond: conditional info for the permission request  (NOT NULL)
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm(int op, const struct path *path, u32 mask,
		       struct path_cond *cond)
{
	struct pyr_profile *profile;
	int error = 0;

	profile = __pyr_current_profile();
	if (!unconfined(profile))
		error = pyr_path_perm(op, profile, path, 0, mask, cond);

	return error;
}

/**
 * common_perm_dir_dentry - common permission wrapper when path is dir, dentry
 * @op: operation being checked
 * @dir: directory of the dentry  (NOT NULL)
 * @dentry: dentry to check  (NOT NULL)
 * @mask: requested permissions mask
 * @cond: conditional info for the permission request  (NOT NULL)
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm_dir_dentry(int op, const struct path *dir,
				  struct dentry *dentry, u32 mask,
				  struct path_cond *cond)
{
	struct path path = { dir->mnt, dentry };

	return common_perm(op, &path, mask, cond);
}

/**
 * common_perm_path - common permission wrapper when mnt, dentry
 * @op: operation being checked
 * @path: location to check (NOT NULL)
 * @mask: requested permissions mask
 *
 * Returns: %0 else error code if error or permission denied
 */
static inline int common_perm_path(int op, const struct path *path, u32 mask)
{
	struct path_cond cond = { d_backing_inode(path->dentry)->i_uid,
				  d_backing_inode(path->dentry)->i_mode
	};
	if (!mediated_filesystem(path->dentry))
		return 0;

	return common_perm(op, path, mask, &cond);
}

/**
 * common_perm_rm - common permission wrapper for operations doing rm
 * @op: operation being checked
 * @dir: directory that the dentry is in  (NOT NULL)
 * @dentry: dentry being rm'd  (NOT NULL)
 * @mask: requested permission mask
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm_rm(int op, const struct path *dir,
			  struct dentry *dentry, u32 mask)
{
	struct inode *inode = d_backing_inode(dentry);
	struct path_cond cond = { };

	if (!inode || !mediated_filesystem(dentry))
		return 0;

	cond.uid = inode->i_uid;
	cond.mode = inode->i_mode;

	return common_perm_dir_dentry(op, dir, dentry, mask, &cond);
}

/**
 * common_perm_create - common permission wrapper for operations doing create
 * @op: operation being checked
 * @dir: directory that dentry will be created in  (NOT NULL)
 * @dentry: dentry to create   (NOT NULL)
 * @mask: request permission mask
 * @mode: created file mode
 *
 * Returns: %0 else error code if error or permission denied
 */
static int common_perm_create(int op, const struct path *dir,
			      struct dentry *dentry, u32 mask, umode_t mode)
{
	struct path_cond cond = { current_fsuid(), mode };

	if (!mediated_filesystem(dir->dentry))
		return 0;

	return common_perm_dir_dentry(op, dir, dentry, mask, &cond);
}

static int pyronia_path_unlink(const struct path *dir, struct dentry *dentry)
{
	return common_perm_rm(OP_UNLINK, dir, dentry, PYR_MAY_DELETE);
}

static int pyronia_path_mkdir(const struct path *dir, struct dentry *dentry,
			       umode_t mode)
{
	return common_perm_create(OP_MKDIR, dir, dentry, PYR_MAY_CREATE,
				  S_IFDIR);
}

static int pyronia_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	return common_perm_rm(OP_RMDIR, dir, dentry, PYR_MAY_DELETE);
}

static int pyronia_path_mknod(const struct path *dir, struct dentry *dentry,
			       umode_t mode, unsigned int dev)
{
	return common_perm_create(OP_MKNOD, dir, dentry, PYR_MAY_CREATE, mode);
}

static int pyronia_path_truncate(const struct path *path)
{
	return common_perm_path(OP_TRUNC, path, MAY_WRITE | PYR_MAY_META_WRITE);
}

static int pyronia_path_symlink(const struct path *dir, struct dentry *dentry,
				 const char *old_name)
{
	return common_perm_create(OP_SYMLINK, dir, dentry, PYR_MAY_CREATE,
				  S_IFLNK);
}

static int pyronia_path_link(struct dentry *old_dentry, const struct path *new_dir,
			      struct dentry *new_dentry)
{
	struct pyr_profile *profile;
	int error = 0;

	if (!mediated_filesystem(old_dentry))
		return 0;

	profile = pyr_current_profile();
	if (!unconfined(profile))
		error = pyr_path_link(profile, old_dentry, new_dir, new_dentry);
	return error;
}

static int pyronia_path_rename(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir, struct dentry *new_dentry)
{
	struct pyr_profile *profile;
	int error = 0;

	if (!mediated_filesystem(old_dentry))
		return 0;

	profile = pyr_current_profile();
	if (!unconfined(profile)) {
		struct path old_path = { old_dir->mnt, old_dentry };
		struct path new_path = { new_dir->mnt, new_dentry };
		struct path_cond cond = { d_backing_inode(old_dentry)->i_uid,
					  d_backing_inode(old_dentry)->i_mode
		};

		error = pyr_path_perm(OP_RENAME_SRC, profile, &old_path, 0,
				     MAY_READ | PYR_MAY_META_READ | MAY_WRITE |
				     PYR_MAY_META_WRITE | PYR_MAY_DELETE,
				     &cond);
		if (!error)
			error = pyr_path_perm(OP_RENAME_DEST, profile, &new_path,
					     0, MAY_WRITE | PYR_MAY_META_WRITE |
					     PYR_MAY_CREATE, &cond);

	}
	return error;
}

static int pyronia_path_chmod(const struct path *path, umode_t mode)
{
	return common_perm_path(OP_CHMOD, path, PYR_MAY_CHMOD);
}

static int pyronia_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	return common_perm_path(OP_CHOWN, path, PYR_MAY_CHOWN);
}

static int pyronia_inode_getattr(const struct path *path)
{
	return common_perm_path(OP_GETATTR, path, PYR_MAY_META_READ);
}

static int pyronia_file_open(struct file *file, const struct cred *cred)
{
	struct pyr_file_cxt *fcxt = file->f_security;
	struct pyr_profile *profile;
	int error = 0;

	if (!mediated_filesystem(file->f_path.dentry))
		return 0;

	/* If in exec, permission is handled by bprm hooks.
	 * Cache permissions granted by the previous exec check, with
	 * implicit read and executable mmap which are required to
	 * actually execute the image.
	 */
	if (current->in_execve) {
		fcxt->allow = MAY_EXEC | MAY_READ | PYR_EXEC_MMAP;
		return 0;
	}

	profile = pyr_cred_profile(cred);
	if (!unconfined(profile)) {
		struct inode *inode = file_inode(file);
		struct path_cond cond = { inode->i_uid, inode->i_mode };

		error = pyr_path_perm(OP_OPEN, profile, &file->f_path, 0,
				     pyr_map_file_to_perms(file), &cond);
		/* todo cache full allowed permissions set and state */
		fcxt->allow = pyr_map_file_to_perms(file);
	}

	return error;
}

static int pyronia_file_alloc_security(struct file *file)
{
	/* freed by pyronia_file_free_security */
	file->f_security = pyr_alloc_file_context(GFP_KERNEL);
	if (!file->f_security)
		return -ENOMEM;
	return 0;

}

static void pyronia_file_free_security(struct file *file)
{
	struct pyr_file_cxt *cxt = file->f_security;

	pyr_free_file_context(cxt);
}

static int common_file_perm(int op, struct file *file, u32 mask)
{
	struct pyr_file_cxt *fcxt = file->f_security;
	struct pyr_profile *profile, *fprofile = pyr_cred_profile(file->f_cred);
	int error = 0;

	BUG_ON(!fprofile);

	if (!file->f_path.mnt ||
	    !mediated_filesystem(file->f_path.dentry))
		return 0;

	profile = __pyr_current_profile();

	/* revalidate access, if task is unconfined, or the cached cred
	 * doesn't match or if the request is for more permissions than
	 * was granted.
	 *
	 * Note: the test for !unconfined(fprofile) is to handle file
	 *       delegation from unconfined tasks
	 */
	if (!unconfined(profile) && !unconfined(fprofile) &&
	    ((fprofile != profile) || (mask & ~fcxt->allow)))
		error = pyr_file_perm(op, profile, file, mask);

	return error;
}

static int pyronia_file_permission(struct file *file, int mask)
{
	return common_file_perm(OP_FPERM, file, mask);
}

static int pyronia_file_lock(struct file *file, unsigned int cmd)
{
	u32 mask = PYR_MAY_LOCK;

	if (cmd == F_WRLCK)
		mask |= MAY_WRITE;

	return common_file_perm(OP_FLOCK, file, mask);
}

static int common_mmap(int op, struct file *file, unsigned long prot,
		       unsigned long flags)
{
	int mask = 0;

	if (!file || !file->f_security)
		return 0;

	if (prot & PROT_READ)
		mask |= MAY_READ;
	/*
	 * Private mappings don't require write perms since they don't
	 * write back to the files
	 */
	if ((prot & PROT_WRITE) && !(flags & MAP_PRIVATE))
		mask |= MAY_WRITE;
	if (prot & PROT_EXEC)
		mask |= PYR_EXEC_MMAP;

	return common_file_perm(op, file, mask);
}

static int pyronia_mmap_file(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags)
{
	return common_mmap(OP_FMMAP, file, prot, flags);
}

static int pyronia_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot, unsigned long prot)
{
	return common_mmap(OP_FMPROT, vma->vm_file, prot,
			   !(vma->vm_flags & VM_SHARED) ? MAP_PRIVATE : 0);
}

static int pyronia_sb_mount(const char *dev_name, const struct path *path,
			     const char *type, unsigned long flags, void *data)
{
	struct pyr_profile *profile;
	int error = 0;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	flags &= ~PYR_MS_IGNORE_MASK;

	profile = __pyr_current_profile();
	if (!unconfined(profile)) {
		if (flags & MS_REMOUNT)
			error = pyr_remount(profile, path, flags, data);
		else if (flags & MS_BIND)
			error = pyr_bind_mount(profile, path, dev_name, flags);
		else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE |
				  MS_UNBINDABLE))
			error = pyr_mount_change_type(profile, path, flags);
		else if (flags & MS_MOVE)
			error = pyr_move_mount(profile, path, dev_name);
		else
			error = pyr_new_mount(profile, dev_name, path, type,
					     flags, data);
	}
	return error;
}

static int pyronia_sb_umount(struct vfsmount *mnt, int flags)
{
	struct pyr_profile *profile;
	int error = 0;

	profile = __pyr_current_profile();
	if (!unconfined(profile))
		error = pyr_umount(profile, mnt, flags);

	return error;
}

static int pyronia_sb_pivotroot(const struct path *old_path,
				 const struct path *new_path)
{
	struct pyr_profile *profile;
	int error = 0;

	profile = __pyr_current_profile();
	if (!unconfined(profile))
		error = pyr_pivotroot(profile, old_path, new_path);

	return error;
}

static int pyronia_getprocattr(struct task_struct *task, char *name,
				char **value)
{
	int error = -ENOENT;
	/* released below */
	const struct cred *cred = get_task_cred(task);
	struct pyr_task_cxt *cxt = cred_cxt(cred);
	struct pyr_profile *profile = NULL;

	if (strcmp(name, "current") == 0)
		profile = pyr_get_newest_profile(cxt->profile);
	else if (strcmp(name, "prev") == 0  && cxt->previous)
		profile = pyr_get_newest_profile(cxt->previous);
	else if (strcmp(name, "exec") == 0 && cxt->onexec)
		profile = pyr_get_newest_profile(cxt->onexec);
	else
		error = -EINVAL;

	if (profile)
		error = pyr_getprocattr(profile, value);

	pyr_put_profile(profile);
	put_cred(cred);

	return error;
}

static int pyronia_setprocattr(struct task_struct *task, char *name,
				void *value, size_t size)
{
	struct common_audit_data sa;
	struct pyronia_audit_data pyrd = {0,};
	char *command, *largs = NULL, *args = value;
	size_t arg_size;
	int error;

	if (size == 0)
		return -EINVAL;
	/* task can only write its own attributes */
	if (current != task)
		return -EACCES;

	/* Pyronia requires that the buffer must be null terminated atm */
	if (args[size - 1] != '\0') {
		/* null terminate */
		largs = args = kmalloc(size + 1, GFP_KERNEL);
		if (!args)
			return -ENOMEM;
		memcpy(args, value, size);
		args[size] = '\0';
	}

	error = -EINVAL;
	args = strim(args);
	command = strsep(&args, " ");
	if (!args)
		goto out;
	args = skip_spaces(args);
	if (!*args)
		goto out;

	arg_size = size - (args - (largs ? largs : (char *) value));
	if (strcmp(name, "current") == 0) {
		if (strcmp(command, "changehat") == 0) {
			error = pyr_setprocattr_changehat(args, arg_size,
							 !PYR_DO_TEST);
		} else if (strcmp(command, "permhat") == 0) {
			error = pyr_setprocattr_changehat(args, arg_size,
							 PYR_DO_TEST);
		} else if (strcmp(command, "changeprofile") == 0) {
			error = pyr_setprocattr_changeprofile(args, !PYR_ONEXEC,
							     !PYR_DO_TEST);
		} else if (strcmp(command, "permprofile") == 0) {
			error = pyr_setprocattr_changeprofile(args, !PYR_ONEXEC,
							     PYR_DO_TEST);
		} else
			goto fail;
	} else if (strcmp(name, "exec") == 0) {
		if (strcmp(command, "exec") == 0)
			error = pyr_setprocattr_changeprofile(args, PYR_ONEXEC,
							     !PYR_DO_TEST);
		else
			goto fail;
	} else
		/* only support the "current" and "exec" process attributes */
		goto fail;

	if (!error)
		error = size;
out:
	kfree(largs);
	return error;

fail:
	sa.type = LSM_AUDIT_DATA_NONE;
	sa.pyrd = &pyrd;
	pyrd.profile = pyr_current_profile();
	pyrd.op = OP_SETPROCATTR;
	pyrd.info = name;
	pyrd.error = error = -EINVAL;
	pyr_audit_msg(AUDIT_PYRONIA_DENIED, &sa, NULL);
	goto out;
}

static int pyronia_task_setrlimit(struct task_struct *task,
		unsigned int resource, struct rlimit *new_rlim)
{
	struct pyr_profile *profile = __pyr_current_profile();
	int error = 0;

	if (!unconfined(profile))
		error = pyr_task_setrlimit(profile, task, resource, new_rlim);

	return error;
}

static int pyronia_socket_create(int family, int type, int protocol, int kern)
{
	struct pyr_profile *profile;
	int error = 0;

	if (kern)
		return 0;

	profile = __pyr_current_profile();
	if (!unconfined(profile))
		error = pyr_net_perm(OP_CREATE, profile, family, type, protocol,
				    NULL);
	return error;
}

static int pyronia_socket_bind(struct socket *sock,
				struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk_addr(OP_BIND, sk, address);
}

static int pyronia_socket_connect(struct socket *sock,
				   struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk_addr(OP_CONNECT, sk, address);
}

static int pyronia_socket_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_LISTEN, sk);
}

static int pyronia_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_ACCEPT, sk);
}

static int pyronia_socket_sendmsg(struct socket *sock,
				   struct msghdr *msg, int size)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_SENDMSG, sk);
}

static int pyronia_socket_recvmsg(struct socket *sock,
				   struct msghdr *msg, int size, int flags)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_RECVMSG, sk);
}

static int pyronia_socket_getsockname(struct socket *sock)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_GETSOCKNAME, sk);
}

static int pyronia_socket_getpeername(struct socket *sock)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_GETPEERNAME, sk);
}

static int pyronia_socket_getsockopt(struct socket *sock, int level,
				      int optname)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_GETSOCKOPT, sk);
}

static int pyronia_socket_setsockopt(struct socket *sock, int level,
				      int optname)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_SETSOCKOPT, sk);
}

static int pyronia_socket_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;

	return pyr_revalidate_sk(OP_SOCK_SHUTDOWN, sk);
}

static struct security_hook_list pyronia_hooks[] = {
	LSM_HOOK_INIT(ptrace_access_check, pyronia_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, pyronia_ptrace_traceme),
	LSM_HOOK_INIT(capget, pyronia_capget),
	LSM_HOOK_INIT(capable, pyronia_capable),

	LSM_HOOK_INIT(sb_mount, pyronia_sb_mount),
	LSM_HOOK_INIT(sb_umount, pyronia_sb_umount),
	LSM_HOOK_INIT(sb_pivotroot, pyronia_sb_pivotroot),
	
	LSM_HOOK_INIT(path_link, pyronia_path_link),
	LSM_HOOK_INIT(path_unlink, pyronia_path_unlink),
	LSM_HOOK_INIT(path_symlink, pyronia_path_symlink),
	LSM_HOOK_INIT(path_mkdir, pyronia_path_mkdir),
	LSM_HOOK_INIT(path_rmdir, pyronia_path_rmdir),
	LSM_HOOK_INIT(path_mknod, pyronia_path_mknod),
	LSM_HOOK_INIT(path_rename, pyronia_path_rename),
	LSM_HOOK_INIT(path_chmod, pyronia_path_chmod),
	LSM_HOOK_INIT(path_chown, pyronia_path_chown),
	LSM_HOOK_INIT(path_truncate, pyronia_path_truncate),
	LSM_HOOK_INIT(inode_getattr, pyronia_inode_getattr),

	LSM_HOOK_INIT(file_open, pyronia_file_open),
	LSM_HOOK_INIT(file_permission, pyronia_file_permission),
	LSM_HOOK_INIT(file_alloc_security, pyronia_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, pyronia_file_free_security),
	LSM_HOOK_INIT(mmap_file, pyronia_mmap_file),
	LSM_HOOK_INIT(file_mprotect, pyronia_file_mprotect),
	LSM_HOOK_INIT(file_lock, pyronia_file_lock),

	LSM_HOOK_INIT(getprocattr, pyronia_getprocattr),
	LSM_HOOK_INIT(setprocattr, pyronia_setprocattr),

	LSM_HOOK_INIT(socket_create, pyronia_socket_create),
	LSM_HOOK_INIT(socket_bind, pyronia_socket_bind),
	LSM_HOOK_INIT(socket_connect, pyronia_socket_connect),
	LSM_HOOK_INIT(socket_listen, pyronia_socket_listen),
	LSM_HOOK_INIT(socket_accept, pyronia_socket_accept),
	LSM_HOOK_INIT(socket_sendmsg, pyronia_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, pyronia_socket_recvmsg),
	LSM_HOOK_INIT(socket_getsockname, pyronia_socket_getsockname),
	LSM_HOOK_INIT(socket_getpeername, pyronia_socket_getpeername),
	LSM_HOOK_INIT(socket_getsockopt, pyronia_socket_getsockopt),
	LSM_HOOK_INIT(socket_setsockopt, pyronia_socket_setsockopt),
	LSM_HOOK_INIT(socket_shutdown, pyronia_socket_shutdown),

	LSM_HOOK_INIT(cred_alloc_blank, pyronia_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, pyronia_cred_free),
	LSM_HOOK_INIT(cred_prepare, pyronia_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, pyronia_cred_transfer),

	LSM_HOOK_INIT(bprm_set_creds, pyronia_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds, pyronia_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, pyronia_bprm_committed_creds),
	LSM_HOOK_INIT(bprm_secureexec, pyronia_bprm_secureexec),

	LSM_HOOK_INIT(task_setrlimit, pyronia_task_setrlimit),
};

/*
 * Pyronia sysfs module parameters
 */

static int param_set_pyrbool(const char *val, const struct kernel_param *kp);
static int param_get_pyrbool(char *buffer, const struct kernel_param *kp);
#define param_check_pyrbool param_check_bool
static const struct kernel_param_ops param_ops_pyrbool = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = param_set_pyrbool,
	.get = param_get_pyrbool
};

static int param_set_pyruint(const char *val, const struct kernel_param *kp);
static int param_get_pyruint(char *buffer, const struct kernel_param *kp);
#define param_check_pyruint param_check_uint
static const struct kernel_param_ops param_ops_pyruint = {
	.set = param_set_pyruint,
	.get = param_get_pyruint
};

static int param_set_pyrlockpolicy(const char *val, const struct kernel_param *kp);
static int param_get_pyrlockpolicy(char *buffer, const struct kernel_param *kp);
#define param_check_pyrlockpolicy param_check_bool
static const struct kernel_param_ops param_ops_pyrlockpolicy = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = param_set_pyrlockpolicy,
	.get = param_get_pyrlockpolicy
};

static int param_set_audit(const char *val, struct kernel_param *kp);
static int param_get_audit(char *buffer, struct kernel_param *kp);

static int param_set_mode(const char *val, struct kernel_param *kp);
static int param_get_mode(char *buffer, struct kernel_param *kp);

/* Flag values, also controllable via /sys/module/pyronia/parameters
 * We define special types as we want to do additional mediation.
 */

/* AppArmor global enforcement switch - complain, enforce, kill */
enum profile_mode pyr_g_profile_mode = PYRONIA_ENFORCE;
module_param_call(mode, param_set_mode, param_get_mode,
		  &pyr_g_profile_mode, S_IRUSR | S_IWUSR);

#ifdef CONFIG_SECURITY_PYRONIA_HASH
/* whether policy verification hashing is enabled */
bool pyr_g_hash_policy = IS_ENABLED(CONFIG_SECURITY_PYRONIA_HASH_DEFAULT);
module_param_named(hash_policy, pyr_g_hash_policy, pyrbool, S_IRUSR | S_IWUSR);
#endif

/* Debug mode */
bool pyr_g_debug = PYR_TESTING;
module_param_named(debug, pyr_g_debug, pyrbool, S_IRUSR | S_IWUSR);

/* Audit mode */
enum audit_mode pyr_g_audit;
module_param_call(audit, param_set_audit, param_get_audit,
		  &pyr_g_audit, S_IRUSR | S_IWUSR);

/* Determines if audit header is included in audited messages.  This
 * provides more context if the audit daemon is not running
 */
bool pyr_g_audit_header = 1;
module_param_named(audit_header, pyr_g_audit_header, pyrbool,
		   S_IRUSR | S_IWUSR);

/* lock out loading/removal of policy
 * TODO: add in at boot loading of policy, which is the only way to
 *       load policy, if lock_policy is set
 */
bool pyr_g_lock_policy;
module_param_named(lock_policy, pyr_g_lock_policy, pyrlockpolicy,
		   S_IRUSR | S_IWUSR);

/* Syscall logging mode */
bool pyr_g_logsyscall;
module_param_named(logsyscall, pyr_g_logsyscall, pyrbool, S_IRUSR | S_IWUSR);

/* Maximum pathname length before accesses will start getting rejected */
unsigned int pyr_g_path_max = 2 * PATH_MAX;
module_param_named(path_max, pyr_g_path_max, pyruint, S_IRUSR | S_IWUSR);

/* Determines how paranoid loading of policy is and how much verification
 * on the loaded policy is done.
 */
bool pyr_g_paranoid_load = 1;
module_param_named(paranoid_load, pyr_g_paranoid_load, pyrbool,
		   S_IRUSR | S_IWUSR);

/* Boot time disable flag */
static bool pyronia_enabled = CONFIG_SECURITY_PYRONIA_BOOTPARAM_VALUE;
module_param_named(enabled, pyronia_enabled, bool, S_IRUGO);

static int __init pyronia_enabled_setup(char *str)
{
	unsigned long enabled;
	int error = kstrtoul(str, 0, &enabled);
	if (!error)
		pyronia_enabled = enabled ? 1 : 0;
	return 1;
}

__setup("pyronia=", pyronia_enabled_setup);

/* set global flag turning off the ability to load policy */
static int param_set_pyrlockpolicy(const char *val, const struct kernel_param *kp)
{
	if (!pyr_policy_admin_capable())
		return -EPERM;
	return param_set_bool(val, kp);
}

static int param_get_pyrlockpolicy(char *buffer, const struct kernel_param *kp)
{
	if (!pyr_policy_view_capable())
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_pyrbool(const char *val, const struct kernel_param *kp)
{
	if (!pyr_policy_admin_capable())
		return -EPERM;
	return param_set_bool(val, kp);
}

static int param_get_pyrbool(char *buffer, const struct kernel_param *kp)
{
	if (!pyr_policy_view_capable())
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_pyruint(const char *val, const struct kernel_param *kp)
{
	if (!pyr_policy_admin_capable())
		return -EPERM;
	return param_set_uint(val, kp);
}

static int param_get_pyruint(char *buffer, const struct kernel_param *kp)
{
	if (!pyr_policy_view_capable())
		return -EPERM;
	return param_get_uint(buffer, kp);
}

static int param_get_audit(char *buffer, struct kernel_param *kp)
{
	if (!pyr_policy_view_capable())
		return -EPERM;

	if (!pyronia_enabled)
		return -EINVAL;

	return sprintf(buffer, "%s", pyr_audit_mode_names[pyr_g_audit]);
}

static int param_set_audit(const char *val, struct kernel_param *kp)
{
	int i;
	if (!pyr_policy_admin_capable())
		return -EPERM;

	if (!pyronia_enabled)
		return -EINVAL;

	if (!val)
		return -EINVAL;

	for (i = 0; i < AUDIT_MAX_INDEX; i++) {
		if (strcmp(val, pyr_audit_mode_names[i]) == 0) {
			pyr_g_audit = i;
			return 0;
		}
	}

	return -EINVAL;
}

static int param_get_mode(char *buffer, struct kernel_param *kp)
{
	if (!pyr_policy_admin_capable())
		return -EPERM;

	if (!pyronia_enabled)
		return -EINVAL;

	return sprintf(buffer, "%s", pyr_profile_mode_names[pyr_g_profile_mode]);
}

static int param_set_mode(const char *val, struct kernel_param *kp)
{
	int i;
	if (!pyr_policy_admin_capable())
		return -EPERM;

	if (!pyronia_enabled)
		return -EINVAL;

	if (!val)
		return -EINVAL;

	for (i = 0; i < PYRONIA_MODE_NAMES_MAX_INDEX; i++) {
		if (strcmp(val, pyr_profile_mode_names[i]) == 0) {
			pyr_g_profile_mode = i;
			return 0;
		}
	}

	return -EINVAL;
}

/*
 * Pyronia init functions
 */

/**
 * set_init_cxt - set a task context and profile on the first task.
 *
 * TODO: allow setting an alternate profile than unconfined
 */
static int __init set_init_cxt(void)
{
	struct cred *cred = (struct cred *)current->real_cred;
	struct pyr_task_cxt *cxt;

	cxt = pyr_alloc_task_context(GFP_KERNEL);
	if (!cxt)
		return -ENOMEM;

	cxt->profile = pyr_get_profile(pyr_root_ns->unconfined);
	cred_cxt(cred) = cxt;

	return 0;
}

static int __init pyronia_init(void)
{
	int error;

	if (!pyronia_enabled || !security_module_enable("pyronia")) {
		pyr_info_message("Pyronia disabled by boot time parameter");
		pyronia_enabled = 0;
		return 0;
	}

	error = pyr_alloc_root_ns();
	if (error) {
		PYR_ERROR("Unable to allocate default profile namespace\n");
		goto alloc_out;
	}

	error = set_init_cxt();
	if (error) {
		PYR_ERROR("Failed to set context on init task\n");
		pyr_free_root_ns();
		goto alloc_out;
	}
	security_add_hooks(pyronia_hooks, ARRAY_SIZE(pyronia_hooks));

	/* Report that Pyronia successfully initialized */
	pyronia_initialized = 1;
	if (pyr_g_profile_mode == PYRONIA_COMPLAIN)
		pyr_info_message("Pyronia initialized: complain mode enabled");
	else if (pyr_g_profile_mode == PYRONIA_KILL)
		pyr_info_message("Pyronia initialized: kill mode enabled");
	else
		pyr_info_message("Pyronia initialized");

	return error;

alloc_out:
	pyr_destroy_pyrfs();

	pyronia_enabled = 0;
	return error;
}

security_initcall(pyronia_init);
