/*
 * AppArmor security module
 *
 * This file contains AppArmor filesystem definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_PYRONIAFS_H
#define __PYR_PYRONIAFS_H

enum pyr_fs_type {
	PYR_FS_TYPE_BOOLEAN,
	PYR_FS_TYPE_STRING,
	PYR_FS_TYPE_U64,
	PYR_FS_TYPE_FOPS,
	PYR_FS_TYPE_DIR,
};

struct pyr_fs_entry;

struct pyr_fs_entry {
	const char *name;
	struct dentry *dentry;
	umode_t mode;
	enum pyr_fs_type v_type;
	union {
		bool boolean;
		char *string;
		unsigned long u64;
		struct pyr_fs_entry *files;
	} v;
	const struct file_operations *file_ops;
};

extern const struct file_operations pyr_fs_seq_file_ops;

#define PYR_FS_FILE_BOOLEAN(_name, _value) \
	{ .name = (_name), .mode = 0444, \
	  .v_type = PYR_FS_TYPE_BOOLEAN, .v.boolean = (_value), \
	  .file_ops = &pyr_fs_seq_file_ops }
#define PYR_FS_FILE_STRING(_name, _value) \
	{ .name = (_name), .mode = 0444, \
	  .v_type = PYR_FS_TYPE_STRING, .v.string = (_value), \
	  .file_ops = &pyr_fs_seq_file_ops }
#define PYR_FS_FILE_U64(_name, _value) \
	{ .name = (_name), .mode = 0444, \
	  .v_type = PYR_FS_TYPE_U64, .v.u64 = (_value), \
	  .file_ops = &pyr_fs_seq_file_ops }
#define PYR_FS_FILE_FOPS(_name, _mode, _fops) \
	{ .name = (_name), .v_type = PYR_FS_TYPE_FOPS, \
	  .mode = (_mode), .file_ops = (_fops) }
#define PYR_FS_DIR(_name, _value) \
	{ .name = (_name), .v_type = PYR_FS_TYPE_DIR, .v.files = (_value) }

extern void __init pyr_destroy_pyrfs(void);

struct pyr_profile;
struct pyr_namespace;

enum pyrfs_ns_type {
	PYRFS_NS_DIR,
	PYRFS_NS_PROFS,
	PYRFS_NS_NS,
	PYRFS_NS_COUNT,
	PYRFS_NS_MAX_COUNT,
	PYRFS_NS_SIZE,
	PYRFS_NS_MAX_SIZE,
	PYRFS_NS_OWNER,
	PYRFS_NS_SIZEOF,
};

enum pyrfs_prof_type {
	PYRFS_PROF_DIR,
	PYRFS_PROF_PROFS,
	PYRFS_PROF_NAME,
	PYRFS_PROF_MODE,
	PYRFS_PROF_ATTACH,
	PYRFS_PROF_HASH,
	PYRFS_PROF_SIZEOF,
};

#define ns_dir(X) ((X)->dents[PYRFS_NS_DIR])
#define ns_subns_dir(X) ((X)->dents[PYRFS_NS_NS])
#define ns_subprofs_dir(X) ((X)->dents[PYRFS_NS_PROFS])

#define prof_dir(X) ((X)->dents[PYRFS_PROF_DIR])
#define prof_child_dir(X) ((X)->dents[PYRFS_PROF_PROFS])

void __pyr_fs_profile_rmdir(struct pyr_profile *profile);
void __pyr_fs_profile_migrate_dents(struct pyr_profile *old,
				   struct pyr_profile *new);
int __pyr_fs_profile_mkdir(struct pyr_profile *profile, struct dentry *parent);
void __pyr_fs_namespace_rmdir(struct pyr_namespace *ns);
int __pyr_fs_namespace_mkdir(struct pyr_namespace *ns, struct dentry *parent,
			    const char *name);

#endif /* __PYR_PYRONIAFS_H */
