/*
 * AppArmor security module
 *
 * This file contains AppArmor /sys/kernel/security/apparmor interface functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/ctype.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/capability.h>
#include <linux/rcupdate.h>

#include "include/pyronia.h"
#include "include/pyroniafs.h"
#include "include/audit.h"
#include "include/context.h"
#include "include/crypto.h"
#include "include/policy.h"
#include "include/resource.h"

/**
 * pyr_mangle_name - mangle a profile name to std profile layout form
 * @name: profile name to mangle  (NOT NULL)
 * @target: buffer to store mangled name, same length as @name (MAYBE NULL)
 *
 * Returns: length of mangled name
 */
static int mangle_name(char *name, char *target)
{
	char *t = target;

	while (*name == '/' || *name == '.')
		name++;

	if (target) {
		for (; *name; name++) {
			if (*name == '/')
				*(t)++ = '.';
			else if (isspace(*name))
				*(t)++ = '_';
			else if (isalnum(*name) || strchr("._-", *name))
				*(t)++ = *name;
		}

		*t = 0;
	} else {
		int len = 0;
		for (; *name; name++) {
			if (isalnum(*name) || isspace(*name) ||
			    strchr("/._-", *name))
				len++;
		}

		return len;
	}

	return t - target;
}

/**
 * pyr_simple_write_to_buffer - common routine for getting policy from user
 * @op: operation doing the user buffer copy
 * @userbuf: user buffer to copy data from  (NOT NULL)
 * @alloc_size: size of user buffer (REQUIRES: @alloc_size >= @copy_size)
 * @copy_size: size of data to copy from user buffer
 * @pos: position write is at in the file (NOT NULL)
 *
 * Returns: kernel buffer containing copy of user buffer data or an
 *          ERR_PTR on failure.
 */
static char *pyr_simple_write_to_buffer(int op, const char __user *userbuf,
				       size_t alloc_size, size_t copy_size,
				       loff_t *pos)
{
	char *data;

	BUG_ON(copy_size > alloc_size);

	if (*pos != 0)
		/* only writes from pos 0, that is complete writes */
		return ERR_PTR(-ESPIPE);

	/*
	 * Don't allow profile load/replace/remove from profiles that don't
	 * have CAP_MAC_ADMIN
	 */
	if (!pyr_may_manage_policy(op))
		return ERR_PTR(-EACCES);

	/* freed by caller to simple_write_to_buffer */
	data = kvmalloc(alloc_size);
	if (data == NULL)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(data, userbuf, copy_size)) {
		kvfree(data);
		return ERR_PTR(-EFAULT);
	}

	return data;
}


/* .load file hook fn to load policy */
static ssize_t profile_load(struct file *f, const char __user *buf, size_t size,
			    loff_t *pos)
{
	char *data;
	ssize_t error;

	data = pyr_simple_write_to_buffer(OP_PROF_LOAD, buf, size, size, pos);

	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		error = pyr_replace_profiles(data, size, PROF_ADD);
		kvfree(data);
	}

	return error;
}

static const struct file_operations pyr_fs_profile_load = {
	.write = profile_load,
	.llseek = default_llseek,
};

/* .replace file hook fn to load and/or replace policy */
static ssize_t profile_replace(struct file *f, const char __user *buf,
			       size_t size, loff_t *pos)
{
	char *data;
	ssize_t error;

	data = pyr_simple_write_to_buffer(OP_PROF_REPL, buf, size, size, pos);
	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		error = pyr_replace_profiles(data, size, PROF_REPLACE);
		kvfree(data);
	}

	return error;
}

static const struct file_operations pyr_fs_profile_replace = {
	.write = profile_replace,
	.llseek = default_llseek,
};

/* .remove file hook fn to remove loaded policy */
static ssize_t profile_remove(struct file *f, const char __user *buf,
			      size_t size, loff_t *pos)
{
	char *data;
	ssize_t error;

	/*
	 * pyr_remove_profile needs a null terminated string so 1 extra
	 * byte is allocated and the copied data is null terminated.
	 */
	data = pyr_simple_write_to_buffer(OP_PROF_RM, buf, size + 1, size, pos);

	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		data[size] = 0;
		error = pyr_remove_profiles(data, size);
		kvfree(data);
	}

	return error;
}

static const struct file_operations pyr_fs_profile_remove = {
	.write = profile_remove,
	.llseek = default_llseek,
};

static int pyr_fs_seq_show(struct seq_file *seq, void *v)
{
	struct pyr_fs_entry *fs_file = seq->private;

	if (!fs_file)
		return 0;

	switch (fs_file->v_type) {
	case PYR_FS_TYPE_BOOLEAN:
		seq_printf(seq, "%s\n", fs_file->v.boolean ? "yes" : "no");
		break;
	case PYR_FS_TYPE_STRING:
		seq_printf(seq, "%s\n", fs_file->v.string);
		break;
	case PYR_FS_TYPE_U64:
		seq_printf(seq, "%#08lx\n", fs_file->v.u64);
		break;
	default:
		/* Ignore unpritable entry types. */
		break;
	}

	return 0;
}

static int pyr_fs_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, pyr_fs_seq_show, inode->i_private);
}

const struct file_operations pyr_fs_seq_file_ops = {
	.owner		= THIS_MODULE,
	.open		= pyr_fs_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int pyr_fs_seq_profile_open(struct inode *inode, struct file *file,
				  int (*show)(struct seq_file *, void *))
{
	struct pyr_replacedby *r = pyr_get_replacedby(inode->i_private);

	 int error = single_open(file, show, r);

	if (error) {
		file->private_data = NULL;
		pyr_put_replacedby(r);
	}

	return error;
}

static int pyr_fs_seq_profile_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = (struct seq_file *) file->private_data;
	if (seq)
		pyr_put_replacedby(seq->private);
	return single_release(inode, file);
}

static int pyr_fs_seq_profname_show(struct seq_file *seq, void *v)
{
	struct pyr_replacedby *r = seq->private;
	struct pyr_profile *profile = pyr_get_profile_rcu(&r->profile);
	seq_printf(seq, "%s\n", profile->base.name);
	pyr_put_profile(profile);

	return 0;
}

static int pyr_fs_seq_profname_open(struct inode *inode, struct file *file)
{
	return pyr_fs_seq_profile_open(inode, file, pyr_fs_seq_profname_show);
}

static const struct file_operations pyr_fs_profname_fops = {
	.owner		= THIS_MODULE,
	.open		= pyr_fs_seq_profname_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= pyr_fs_seq_profile_release,
};

static int pyr_fs_seq_profmode_show(struct seq_file *seq, void *v)
{
	struct pyr_replacedby *r = seq->private;
	struct pyr_profile *profile = pyr_get_profile_rcu(&r->profile);
	seq_printf(seq, "%s\n", pyr_profile_mode_names[profile->mode]);
	pyr_put_profile(profile);

	return 0;
}

static int pyr_fs_seq_profmode_open(struct inode *inode, struct file *file)
{
	return pyr_fs_seq_profile_open(inode, file, pyr_fs_seq_profmode_show);
}

static const struct file_operations pyr_fs_profmode_fops = {
	.owner		= THIS_MODULE,
	.open		= pyr_fs_seq_profmode_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= pyr_fs_seq_profile_release,
};

static int pyr_fs_seq_profattach_show(struct seq_file *seq, void *v)
{
	struct pyr_replacedby *r = seq->private;
	struct pyr_profile *profile = pyr_get_profile_rcu(&r->profile);
	if (profile->attach)
		seq_printf(seq, "%s\n", profile->attach);
	else if (profile->xmatch)
		seq_puts(seq, "<unknown>\n");
	else
		seq_printf(seq, "%s\n", profile->base.name);
	pyr_put_profile(profile);

	return 0;
}

static int pyr_fs_seq_profattach_open(struct inode *inode, struct file *file)
{
	return pyr_fs_seq_profile_open(inode, file, pyr_fs_seq_profattach_show);
}

static const struct file_operations pyr_fs_profattach_fops = {
	.owner		= THIS_MODULE,
	.open		= pyr_fs_seq_profattach_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= pyr_fs_seq_profile_release,
};

static int pyr_fs_seq_hash_show(struct seq_file *seq, void *v)
{
	struct pyr_replacedby *r = seq->private;
	struct pyr_profile *profile = pyr_get_profile_rcu(&r->profile);
	unsigned int i, size = pyr_hash_size();

	if (profile->hash) {
		for (i = 0; i < size; i++)
			seq_printf(seq, "%.2x", profile->hash[i]);
		seq_puts(seq, "\n");
	}
	pyr_put_profile(profile);

	return 0;
}

static int pyr_fs_seq_hash_open(struct inode *inode, struct file *file)
{
	return single_open(file, pyr_fs_seq_hash_show, inode->i_private);
}

static const struct file_operations pyr_fs_seq_hash_fops = {
	.owner		= THIS_MODULE,
	.open		= pyr_fs_seq_hash_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/** fns to setup dynamic per profile/namespace files **/
void __pyr_fs_profile_rmdir(struct pyr_profile *profile)
{
	struct pyr_profile *child;
	int i;

	if (!profile)
		return;

	list_for_each_entry(child, &profile->base.profiles, base.list)
		__pyr_fs_profile_rmdir(child);

	for (i = PYRFS_PROF_SIZEOF - 1; i >= 0; --i) {
		struct pyr_replacedby *r;
		if (!profile->dents[i])
			continue;

		r = d_inode(profile->dents[i])->i_private;
		securityfs_remove(profile->dents[i]);
		pyr_put_replacedby(r);
		profile->dents[i] = NULL;
	}
}

void __pyr_fs_profile_migrate_dents(struct pyr_profile *old,
				   struct pyr_profile *new)
{
	int i;

	for (i = 0; i < PYRFS_PROF_SIZEOF; i++) {
		new->dents[i] = old->dents[i];
		if (new->dents[i])
			new->dents[i]->d_inode->i_mtime = CURRENT_TIME;
		old->dents[i] = NULL;
	}
}

static struct dentry *create_profile_file(struct dentry *dir, const char *name,
					  struct pyr_profile *profile,
					  const struct file_operations *fops)
{
	struct pyr_replacedby *r = pyr_get_replacedby(profile->replacedby);
	struct dentry *dent;

	dent = securityfs_create_file(name, S_IFREG | 0444, dir, r, fops);
	if (IS_ERR(dent))
		pyr_put_replacedby(r);

	return dent;
}

/* requires lock be held */
int __pyr_fs_profile_mkdir(struct pyr_profile *profile, struct dentry *parent)
{
	struct pyr_profile *child;
	struct dentry *dent = NULL, *dir;
	int error;

	if (!parent) {
		struct pyr_profile *p;
		p = pyr_deref_parent(profile);
		dent = prof_dir(p);
		/* adding to parent that previously didn't have children */
		dent = securityfs_create_dir("profiles", dent);
		if (IS_ERR(dent))
			goto fail;
		prof_child_dir(p) = parent = dent;
	}

	if (!profile->dirname) {
		int len, id_len;
		len = mangle_name(profile->base.name, NULL);
		id_len = snprintf(NULL, 0, ".%ld", profile->ns->uniq_id);

		profile->dirname = kmalloc(len + id_len + 1, GFP_KERNEL);
		if (!profile->dirname)
			goto fail;

		mangle_name(profile->base.name, profile->dirname);
		sprintf(profile->dirname + len, ".%ld", profile->ns->uniq_id++);
	}

	dent = securityfs_create_dir(profile->dirname, parent);
	if (IS_ERR(dent))
		goto fail;
	prof_dir(profile) = dir = dent;

	dent = create_profile_file(dir, "name", profile, &pyr_fs_profname_fops);
	if (IS_ERR(dent))
		goto fail;
	profile->dents[PYRFS_PROF_NAME] = dent;

	dent = create_profile_file(dir, "mode", profile, &pyr_fs_profmode_fops);
	if (IS_ERR(dent))
		goto fail;
	profile->dents[PYRFS_PROF_MODE] = dent;

	dent = create_profile_file(dir, "attach", profile,
				   &pyr_fs_profattach_fops);
	if (IS_ERR(dent))
		goto fail;
	profile->dents[PYRFS_PROF_ATTACH] = dent;

	if (profile->hash) {
		dent = create_profile_file(dir, "sha1", profile,
					   &pyr_fs_seq_hash_fops);
		if (IS_ERR(dent))
			goto fail;
		profile->dents[PYRFS_PROF_HASH] = dent;
	}

	list_for_each_entry(child, &profile->base.profiles, base.list) {
		error = __pyr_fs_profile_mkdir(child, prof_child_dir(profile));
		if (error)
			goto fail2;
	}

	return 0;

fail:
	error = PTR_ERR(dent);

fail2:
	__pyr_fs_profile_rmdir(profile);

	return error;
}

void __pyr_fs_namespace_rmdir(struct pyr_namespace *ns)
{
	struct pyr_namespace *sub;
	struct pyr_profile *child;
	int i;

	if (!ns)
		return;

	list_for_each_entry(child, &ns->base.profiles, base.list)
		__pyr_fs_profile_rmdir(child);

	list_for_each_entry(sub, &ns->sub_ns, base.list) {
		mutex_lock(&sub->lock);
		__pyr_fs_namespace_rmdir(sub);
		mutex_unlock(&sub->lock);
	}

	for (i = PYRFS_NS_SIZEOF - 1; i >= 0; --i) {
		securityfs_remove(ns->dents[i]);
		ns->dents[i] = NULL;
	}
}

int __pyr_fs_namespace_mkdir(struct pyr_namespace *ns, struct dentry *parent,
			    const char *name)
{
	struct pyr_namespace *sub;
	struct pyr_profile *child;
	struct dentry *dent, *dir;
	int error;

	if (!name)
		name = ns->base.name;

	dent = securityfs_create_dir(name, parent);
	if (IS_ERR(dent))
		goto fail;
	ns_dir(ns) = dir = dent;

	dent = securityfs_create_dir("profiles", dir);
	if (IS_ERR(dent))
		goto fail;
	ns_subprofs_dir(ns) = dent;

	dent = securityfs_create_dir("namespaces", dir);
	if (IS_ERR(dent))
		goto fail;
	ns_subns_dir(ns) = dent;

	list_for_each_entry(child, &ns->base.profiles, base.list) {
		error = __pyr_fs_profile_mkdir(child, ns_subprofs_dir(ns));
		if (error)
			goto fail2;
	}

	list_for_each_entry(sub, &ns->sub_ns, base.list) {
		mutex_lock(&sub->lock);
		error = __pyr_fs_namespace_mkdir(sub, ns_subns_dir(ns), NULL);
		mutex_unlock(&sub->lock);
		if (error)
			goto fail2;
	}

	return 0;

fail:
	error = PTR_ERR(dent);

fail2:
	__pyr_fs_namespace_rmdir(ns);

	return error;
}


#define list_entry_is_head(pos, head, member) (&pos->member == (head))

/**
 * __next_namespace - find the next namespace to list
 * @root: root namespace to stop search at (NOT NULL)
 * @ns: current ns position (NOT NULL)
 *
 * Find the next namespace from @ns under @root and handle all locking needed
 * while switching current namespace.
 *
 * Returns: next namespace or NULL if at last namespace under @root
 * Requires: ns->parent->lock to be held
 * NOTE: will not unlock root->lock
 */
static struct pyr_namespace *__next_namespace(struct pyr_namespace *root,
					     struct pyr_namespace *ns)
{
	struct pyr_namespace *parent, *next;

	/* is next namespace a child */
	if (!list_empty(&ns->sub_ns)) {
		next = list_first_entry(&ns->sub_ns, typeof(*ns), base.list);
		mutex_lock(&next->lock);
		return next;
	}

	/* check if the next ns is a sibling, parent, gp, .. */
	parent = ns->parent;
	while (ns != root) {
		mutex_unlock(&ns->lock);
		next = list_next_entry(ns, base.list);
		if (!list_entry_is_head(next, &parent->sub_ns, base.list)) {
			mutex_lock(&next->lock);
			return next;
		}
		ns = parent;
		parent = parent->parent;
	}

	return NULL;
}

/**
 * __first_profile - find the first profile in a namespace
 * @root: namespace that is root of profiles being displayed (NOT NULL)
 * @ns: namespace to start in   (NOT NULL)
 *
 * Returns: unrefcounted profile or NULL if no profile
 * Requires: profile->ns.lock to be held
 */
static struct pyr_profile *__first_profile(struct pyr_namespace *root,
					  struct pyr_namespace *ns)
{
	for (; ns; ns = __next_namespace(root, ns)) {
		if (!list_empty(&ns->base.profiles))
			return list_first_entry(&ns->base.profiles,
						struct pyr_profile, base.list);
	}
	return NULL;
}

/**
 * __next_profile - step to the next profile in a profile tree
 * @profile: current profile in tree (NOT NULL)
 *
 * Perform a depth first traversal on the profile tree in a namespace
 *
 * Returns: next profile or NULL if done
 * Requires: profile->ns.lock to be held
 */
static struct pyr_profile *__next_profile(struct pyr_profile *p)
{
	struct pyr_profile *parent;
	struct pyr_namespace *ns = p->ns;

	/* is next profile a child */
	if (!list_empty(&p->base.profiles))
		return list_first_entry(&p->base.profiles, typeof(*p),
					base.list);

	/* is next profile a sibling, parent sibling, gp, sibling, .. */
	parent = rcu_dereference_protected(p->parent,
					   mutex_is_locked(&p->ns->lock));
	while (parent) {
		p = list_next_entry(p, base.list);
		if (!list_entry_is_head(p, &parent->base.profiles, base.list))
			return p;
		p = parent;
		parent = rcu_dereference_protected(parent->parent,
					    mutex_is_locked(&parent->ns->lock));
	}

	/* is next another profile in the namespace */
	p = list_next_entry(p, base.list);
	if (!list_entry_is_head(p, &ns->base.profiles, base.list))
		return p;

	return NULL;
}

/**
 * next_profile - step to the next profile in where ever it may be
 * @root: root namespace  (NOT NULL)
 * @profile: current profile  (NOT NULL)
 *
 * Returns: next profile or NULL if there isn't one
 */
static struct pyr_profile *next_profile(struct pyr_namespace *root,
				       struct pyr_profile *profile)
{
	struct pyr_profile *next = __next_profile(profile);
	if (next)
		return next;

	/* finished all profiles in namespace move to next namespace */
	return __first_profile(root, __next_namespace(root, profile->ns));
}

/**
 * p_start - start a depth first traversal of profile tree
 * @f: seq_file to fill
 * @pos: current position
 *
 * Returns: first profile under current namespace or NULL if none found
 *
 * acquires first ns->lock
 */
static void *p_start(struct seq_file *f, loff_t *pos)
{
	struct pyr_profile *profile = NULL;
	struct pyr_namespace *root = pyr_current_profile()->ns;
	loff_t l = *pos;
	f->private = pyr_get_namespace(root);


	/* find the first profile */
	mutex_lock(&root->lock);
	profile = __first_profile(root, root);

	/* skip to position */
	for (; profile && l > 0; l--)
		profile = next_profile(root, profile);

	return profile;
}

/**
 * p_next - read the next profile entry
 * @f: seq_file to fill
 * @p: profile previously returned
 * @pos: current position
 *
 * Returns: next profile after @p or NULL if none
 *
 * may acquire/release locks in namespace tree as necessary
 */
static void *p_next(struct seq_file *f, void *p, loff_t *pos)
{
	struct pyr_profile *profile = p;
	struct pyr_namespace *ns = f->private;
	(*pos)++;

	return next_profile(ns, profile);
}

/**
 * p_stop - stop depth first traversal
 * @f: seq_file we are filling
 * @p: the last profile writen
 *
 * Release all locking done by p_start/p_next on namespace tree
 */
static void p_stop(struct seq_file *f, void *p)
{
	struct pyr_profile *profile = p;
	struct pyr_namespace *root = f->private, *ns;

	if (profile) {
		for (ns = profile->ns; ns && ns != root; ns = ns->parent)
			mutex_unlock(&ns->lock);
	}
	mutex_unlock(&root->lock);
	pyr_put_namespace(root);
}

/**
 * seq_show_profile - show a profile entry
 * @f: seq_file to file
 * @p: current position (profile)    (NOT NULL)
 *
 * Returns: error on failure
 */
static int seq_show_profile(struct seq_file *f, void *p)
{
	struct pyr_profile *profile = (struct pyr_profile *)p;
	struct pyr_namespace *root = f->private;

	if (profile->ns != root)
		seq_printf(f, ":%s://", pyr_ns_name(root, profile->ns));
	seq_printf(f, "%s (%s)\n", profile->base.hname,
		   pyr_profile_mode_names[profile->mode]);

	return 0;
}

static const struct seq_operations pyr_fs_profiles_op = {
	.start = p_start,
	.next = p_next,
	.stop = p_stop,
	.show = seq_show_profile,
};

static int pyr_profiles_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &pyr_fs_profiles_op);
}

static int pyr_profiles_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static const struct file_operations pyr_fs_profiles_fops = {
	.open = pyr_profiles_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = pyr_profiles_release,
};


/** Base file system setup **/
static struct pyr_fs_entry pyr_fs_entry_file[] = {
	PYR_FS_FILE_STRING("mask", "create read write exec append mmap_exec " \
				  "link lock"),
	{ }
};

static struct pyr_fs_entry pyr_fs_entry_domain[] = {
	PYR_FS_FILE_BOOLEAN("change_hat",	1),
	PYR_FS_FILE_BOOLEAN("change_hatv",	1),
	PYR_FS_FILE_BOOLEAN("change_onexec",	1),
	PYR_FS_FILE_BOOLEAN("change_profile",	1),
	{ }
};

static struct pyr_fs_entry pyr_fs_entry_policy[] = {
	PYR_FS_FILE_BOOLEAN("set_load",          1),
	{ }
};

static struct pyr_fs_entry pyr_fs_entry_mount[] = {
	PYR_FS_FILE_STRING("mask", "mount umount"),
	{ }
};

static struct pyr_fs_entry pyr_fs_entry_namespaces[] = {
	PYR_FS_FILE_BOOLEAN("profile",           1),
	PYR_FS_FILE_BOOLEAN("pivot_root",        1),
	{ }
};

static struct pyr_fs_entry pyr_fs_entry_features[] = {
	PYR_FS_DIR("policy",			pyr_fs_entry_policy),
	PYR_FS_DIR("domain",			pyr_fs_entry_domain),
	PYR_FS_DIR("file",			pyr_fs_entry_file),
	PYR_FS_DIR("network",                    pyr_fs_entry_network),
	PYR_FS_DIR("mount",                      pyr_fs_entry_mount),
	PYR_FS_DIR("namespaces",                 pyr_fs_entry_namespaces),
	PYR_FS_FILE_U64("capability",		VFS_CAP_FLAGS_MASK),
	PYR_FS_DIR("rlimit",			pyr_fs_entry_rlimit),
	PYR_FS_DIR("caps",			pyr_fs_entry_caps),
	{ }
};

static struct pyr_fs_entry pyr_fs_entry_pyronia[] = {
	PYR_FS_FILE_FOPS(".load", 0640, &pyr_fs_profile_load),
	PYR_FS_FILE_FOPS(".replace", 0640, &pyr_fs_profile_replace),
	PYR_FS_FILE_FOPS(".remove", 0640, &pyr_fs_profile_remove),
	PYR_FS_FILE_FOPS("profiles", 0640, &pyr_fs_profiles_fops),
	PYR_FS_DIR("features", pyr_fs_entry_features),
	{ }
};

static struct pyr_fs_entry pyr_fs_entry =
	PYR_FS_DIR("pyronia", pyr_fs_entry_pyronia);

/**
 * pyrfs_create_file - create a file entry in the pyronia securityfs
 * @fs_file: pyr_fs_entry to build an entry for (NOT NULL)
 * @parent: the parent dentry in the securityfs
 *
 * Use pyrfs_remove_file to remove entries created with this fn.
 */
static int __init pyrfs_create_file(struct pyr_fs_entry *fs_file,
				   struct dentry *parent)
{
	int error = 0;

	fs_file->dentry = securityfs_create_file(fs_file->name,
						 S_IFREG | fs_file->mode,
						 parent, fs_file,
						 fs_file->file_ops);
	if (IS_ERR(fs_file->dentry)) {
		error = PTR_ERR(fs_file->dentry);
		fs_file->dentry = NULL;
	}
	return error;
}

static void __init pyrfs_remove_dir(struct pyr_fs_entry *fs_dir);
/**
 * pyrfs_create_dir - recursively create a directory entry in the securityfs
 * @fs_dir: pyr_fs_entry (and all child entries) to build (NOT NULL)
 * @parent: the parent dentry in the securityfs
 *
 * Use pyrfs_remove_dir to remove entries created with this fn.
 */
static int __init pyrfs_create_dir(struct pyr_fs_entry *fs_dir,
				  struct dentry *parent)
{
	struct pyr_fs_entry *fs_file;
	struct dentry *dir;
	int error;

	dir = securityfs_create_dir(fs_dir->name, parent);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	fs_dir->dentry = dir;

	for (fs_file = fs_dir->v.files; fs_file && fs_file->name; ++fs_file) {
		if (fs_file->v_type == PYR_FS_TYPE_DIR)
			error = pyrfs_create_dir(fs_file, fs_dir->dentry);
		else
			error = pyrfs_create_file(fs_file, fs_dir->dentry);
		if (error)
			goto failed;
	}

	return 0;

failed:
	pyrfs_remove_dir(fs_dir);

	return error;
}

/**
 * pyrfs_remove_file - drop a single file entry in the pyronia securityfs
 * @fs_file: pyr_fs_entry to detach from the securityfs (NOT NULL)
 */
static void __init pyrfs_remove_file(struct pyr_fs_entry *fs_file)
{
	if (!fs_file->dentry)
		return;

	securityfs_remove(fs_file->dentry);
	fs_file->dentry = NULL;
}

/**
 * pyrfs_remove_dir - recursively drop a directory entry from the securityfs
 * @fs_dir: pyr_fs_entry (and all child entries) to detach (NOT NULL)
 */
static void __init pyrfs_remove_dir(struct pyr_fs_entry *fs_dir)
{
	struct pyr_fs_entry *fs_file;

	for (fs_file = fs_dir->v.files; fs_file && fs_file->name; ++fs_file) {
		if (fs_file->v_type == PYR_FS_TYPE_DIR)
			pyrfs_remove_dir(fs_file);
		else
			pyrfs_remove_file(fs_file);
	}

	pyrfs_remove_file(fs_dir);
}

/**
 * pyr_destroy_pyrfs - cleanup and free pyrfs
 *
 * releases dentries allocated by pyr_create_pyrfs
 */
void __init pyr_destroy_pyrfs(void)
{
	pyrfs_remove_dir(&pyr_fs_entry);
}

/**
 * pyr_create_pyrfs - create the pyronia security filesystem
 *
 * dentries created here are released by pyr_destroy_pyrfs
 *
 * Returns: error on failure
 */
static int __init pyr_create_pyrfs(void)
{
	int error;

	if (!pyronia_initialized)
		return 0;

	if (pyr_fs_entry.dentry) {
		PYR_ERROR("%s: Pyronia securityfs already exists\n", __func__);
		return -EEXIST;
	}

	/* Populate fs tree. */
	error = pyrfs_create_dir(&pyr_fs_entry, NULL);
	if (error)
		goto error;

	error = __pyr_fs_namespace_mkdir(pyr_root_ns, pyr_fs_entry.dentry,
					"policy");
	if (error)
		goto error;

	/* TODO: add support for pyroniafs_null and pyroniafs_mnt */

	/* Report that Pyronia fs is enabled */
	pyr_info_message("Pyronia Filesystem Enabled");
	return 0;

error:
	pyr_destroy_pyrfs();
	PYR_ERROR("Error creating Pyronia securityfs\n");
	return error;
}

fs_initcall(pyr_create_pyrfs);
