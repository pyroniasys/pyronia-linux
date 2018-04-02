/*
 * AppArmor security module
 *
 * This file contains AppArmor policy definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_POLICY_H
#define __PYR_POLICY_H

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>

#include "pyronia.h"
#include "audit.h"
#include "capability.h"
#include "domain.h"
#include "file.h"
#include "net.h"
#include "resource.h"
#include "lib_policy.h"

extern const char *const pyr_profile_mode_names[];
#define PYRONIA_MODE_NAMES_MAX_INDEX 4

#define PROFILE_MODE(_profile, _mode)		\
	((pyr_g_profile_mode == (_mode)) ||	\
	 ((_profile)->mode == (_mode)))

#define COMPLAIN_MODE(_profile)	PROFILE_MODE((_profile), PYRONIA_COMPLAIN)

#define KILL_MODE(_profile) PROFILE_MODE((_profile), PYRONIA_KILL)

#define PROFILE_IS_HAT(_profile) ((_profile)->flags & PFLAG_HAT)

#define PROFILE_INVALID(_profile) ((_profile)->flags & PFLAG_INVALID)

#define on_list_rcu(X) (!list_empty(X) && (X)->prev != LIST_POISON2)

/*
 * FIXME: currently need a clean way to replace and remove profiles as a
 * set.  It should be done at the namespace level.
 * Either, with a set of profiles loaded at the namespace level or via
 * a mark and remove marked interface.
 */
enum profile_mode {
	PYRONIA_ENFORCE,	/* enforce access rules */
	PYRONIA_COMPLAIN,	/* allow and log access violations */
	PYRONIA_KILL,		/* kill task on access violation */
	PYRONIA_UNCONFINED,	/* profile set to unconfined */
};

enum profile_flags {
	PFLAG_HAT = 1,			/* profile is a hat */
	PFLAG_NULL = 4,			/* profile is null learning profile */
	PFLAG_IX_ON_NAME_ERROR = 8,	/* fallback to ix on name lookup fail */
	PFLAG_IMMUTABLE = 0x10,		/* don't allow changes/replacement */
	PFLAG_USER_DEFINED = 0x20,	/* user based profile - lower privs */
	PFLAG_NO_LIST_REF = 0x40,	/* list doesn't keep profile ref */
	PFLAG_OLD_NULL_TRANS = 0x100,	/* use // as the null transition */
	PFLAG_INVALID = 0x200,		/* profile replaced/removed */
	PFLAG_NS_COUNT = 0x400,		/* carries NS ref count */

	/* These flags must correspond with PATH_flags */
	PFLAG_MEDIATE_DELETED = 0x10000, /* mediate instead delegate deleted */
};

struct pyr_profile;

/* struct pyr_policy - common part of both namespaces and profiles
 * @name: name of the object
 * @hname - The hierarchical name
 * @list: list policy object is on
 * @profiles: head of the profiles list contained in the object
 */
struct pyr_policy {
	char *name;
	char *hname;
	struct list_head list;
	struct list_head profiles;
};

/* struct pyr_ns_acct - accounting of profiles in namespace
 * @max_size: maximum space allowed for all profiles in namespace
 * @max_count: maximum number of profiles that can be in this namespace
 * @size: current size of profiles
 * @count: current count of profiles (includes null profiles)
 */
struct pyr_ns_acct {
	int max_size;
	int max_count;
	int size;
	int count;
};

/* struct pyr_namespace - namespace for a set of profiles
 * @base: common policy
 * @parent: parent of namespace
 * @lock: lock for modifying the object
 * @acct: accounting for the namespace
 * @unconfined: special unconfined profile for the namespace
 * @sub_ns: list of namespaces under the current namespace.
 * @uniq_null: uniq value used for null learning profiles
 * @uniq_id: a unique id count for the profiles in the namespace
 * @dents: dentries for the namespaces file entries in pyroniafs
 *
 * An pyr_namespace defines the set profiles that are searched to determine
 * which profile to attach to a task.  Profiles can not be shared between
 * pyr_namespaces and profile names within a namespace are guaranteed to be
 * unique.  When profiles in separate namespaces have the same name they
 * are NOT considered to be equivalent.
 *
 * Namespaces are hierarchical and only namespaces and profiles below the
 * current namespace are visible.
 *
 * Namespace names must be unique and can not contain the characters :/\0
 *
 * FIXME TODO: add vserver support of namespaces (can it all be done in
 *             userspace?)
 */
struct pyr_namespace {
	struct pyr_policy base;
	struct pyr_namespace *parent;
	struct mutex lock;
	struct pyr_ns_acct acct;
	struct pyr_profile *unconfined;
	struct list_head sub_ns;
	atomic_t uniq_null;
	long uniq_id;

	struct dentry *dents[PYRFS_NS_SIZEOF];
};

/* struct pyr_policydb - match engine for a policy
 * dfa: dfa pattern match
 * start: set of start states for the different classes of data
 */
struct pyr_policydb {
	/* Generic policy DFA specific rule types will be subsections of it */
    struct pyr_dfa *dfa;
    unsigned int start[PYR_CLASS_LAST + 1];

};

struct pyr_replacedby {
	struct kref count;
	struct pyr_profile __rcu *profile;
};


/* struct pyr_profile - basic confinement data
 * @base - base components of the profile (name, refcount, lists, lock ...)
 * @count: reference count of the obj
 * @rcu: rcu head used when removing from @list
 * @parent: parent of profile
 * @ns: namespace the profile is in
 * @replacedby: is set to the profile that replaced this profile
 * @rename: optional profile name that this profile renamed
 * @attach: human readable attachment string
 * @xmatch: optional extended matching for unconfined executables names
 * @xmatch_len: xmatch prefix len, used to determine xmatch priority
 * @audit: the auditing mode of the profile
 * @mode: the enforcement mode of the profile
 * @flags: flags controlling profile behavior
 * @path_flags: flags controlling path generation behavior
 * @size: the memory consumed by this profiles rules
 * @policy: general match rules governing policy
 * @file: The set of rules governing basic file access and domain transitions
 * @caps: capabilities for the profile
 * @net: network controls for the profile
 * @rlimits: rlimits for the profile
 * @lib_perm_db: the library-specific permissions for the profile
 * @port_id: the stack inspection port for this profile's application
 * @using_pyronia: flag indicating whether the confined application should 
 * be subject to stack inspection checks.
 *
 *
 * @dents: dentries for the profiles file entries in pyroniafs
 * @dirname: name of the profile dir in pyroniafs
 *
 * The Pyronia profile contains the basic confinement data.  Each profile
 * has a name, and exists in a namespace.  The @name and @exec_match are
 * used to determine profile attachment against unconfined tasks.  All other
 * attachments are determined by profile X transition rules.
 *
 * The @replacedby struct is write protected by the profile lock.
 *
 * Profiles have a hierarchy where hats and children profiles keep
 * a reference to their parent.
 *
 * Profile names can not begin with a : and can not contain the \0
 * character.  If a profile name begins with / it will be considered when
 * determining profile attachment on "unconfined" tasks.
 */
struct pyr_profile {
	struct pyr_policy base;
	struct kref count;
	struct rcu_head rcu;
	struct pyr_profile __rcu *parent;

	struct pyr_namespace *ns;
	struct pyr_replacedby *replacedby;
	const char *rename;

	const char *attach;
	struct pyr_dfa *xmatch;
	int xmatch_len;
	enum audit_mode audit;
	long mode;
	long flags;
	u32 path_flags;
	int size;

	struct pyr_policydb policy;
	struct pyr_file_rules file;
	struct pyr_caps caps;
	struct pyr_net net;
	struct pyr_rlimit rlimits;
        struct pyr_lib_policy_db *lib_perm_db;
        u32 port_id;
        int using_pyronia;

	unsigned char *hash;
	char *dirname;
	struct dentry *dents[PYRFS_PROF_SIZEOF];
};

extern struct pyr_namespace *pyr_root_ns;
extern enum profile_mode pyr_g_profile_mode;

void pyr_add_profile(struct pyr_policy *common, struct pyr_profile *profile);

bool pyr_ns_visible(struct pyr_namespace *curr, struct pyr_namespace *view);
const char *pyr_ns_name(struct pyr_namespace *parent, struct pyr_namespace *child);
int pyr_alloc_root_ns(void);
void pyr_free_root_ns(void);
void pyr_free_namespace_kref(struct kref *kref);

struct pyr_namespace *pyr_find_namespace(struct pyr_namespace *root,
				       const char *name);


void pyr_free_replacedby_kref(struct kref *kref);
struct pyr_profile *pyr_alloc_profile(const char *name);
struct pyr_profile *pyr_new_null_profile(struct pyr_profile *parent, int hat);
void pyr_free_profile(struct pyr_profile *profile);
void pyr_free_profile_kref(struct kref *kref);
struct pyr_profile *pyr_find_child(struct pyr_profile *parent, const char *name);
struct pyr_profile *pyr_lookup_profile(struct pyr_namespace *ns, const char *name);
struct pyr_profile *pyr_match_profile(struct pyr_namespace *ns, const char *name);

ssize_t pyr_replace_profiles(void *udata, size_t size, bool noreplace);
ssize_t pyr_remove_profiles(char *name, size_t size);

#define PROF_ADD 1
#define PROF_REPLACE 0

#define unconfined(X) ((X)->mode == PYRONIA_UNCONFINED)


static inline struct pyr_profile *pyr_deref_parent(struct pyr_profile *p)
{
	return rcu_dereference_protected(p->parent,
					 mutex_is_locked(&p->ns->lock));
}

/**
 * pyr_get_profile - increment refcount on profile @p
 * @p: profile  (MAYBE NULL)
 *
 * Returns: pointer to @p if @p is NULL will return NULL
 * Requires: @p must be held with valid refcount when called
 */
static inline struct pyr_profile *pyr_get_profile(struct pyr_profile *p)
{
	if (p)
		kref_get(&(p->count));

	return p;
}

/**
 * pyr_get_profile_not0 - increment refcount on profile @p found via lookup
 * @p: profile  (MAYBE NULL)
 *
 * Returns: pointer to @p if @p is NULL will return NULL
 * Requires: @p must be held with valid refcount when called
 */
static inline struct pyr_profile *pyr_get_profile_not0(struct pyr_profile *p)
{
	if (p && kref_get_not0(&p->count))
		return p;

	return NULL;
}

/**
 * pyr_get_profile_rcu - increment a refcount profile that can be replaced
 * @p: pointer to profile that can be replaced (NOT NULL)
 *
 * Returns: pointer to a refcounted profile.
 *     else NULL if no profile
 */
static inline struct pyr_profile *pyr_get_profile_rcu(struct pyr_profile __rcu **p)
{
	struct pyr_profile *c;

	rcu_read_lock();
	do {
		c = rcu_dereference(*p);
	} while (c && !kref_get_not0(&c->count));
	rcu_read_unlock();

	return c;
}

/**
 * pyr_get_newest_profile - find the newest version of @profile
 * @profile: the profile to check for newer versions of
 *
 * Returns: refcounted newest version of @profile taking into account
 *          replacement, renames and removals
 *          return @profile.
 */
static inline struct pyr_profile *pyr_get_newest_profile(struct pyr_profile *p)
{
	if (!p)
		return NULL;

	if (PROFILE_INVALID(p))
		return pyr_get_profile_rcu(&p->replacedby->profile);

	return pyr_get_profile(p);
}

/**
 * pyr_put_profile - decrement refcount on profile @p
 * @p: profile  (MAYBE NULL)
 */
static inline void pyr_put_profile(struct pyr_profile *p)
{
	if (p)
		kref_put(&p->count, pyr_free_profile_kref);
}

static inline struct pyr_replacedby *pyr_get_replacedby(struct pyr_replacedby *p)
{
	if (p)
		kref_get(&(p->count));

	return p;
}

static inline void pyr_put_replacedby(struct pyr_replacedby *p)
{
	if (p)
		kref_put(&p->count, pyr_free_replacedby_kref);
}

/* requires profile list write lock held */
static inline void __pyr_update_replacedby(struct pyr_profile *orig,
					  struct pyr_profile *new)
{
	struct pyr_profile *tmp;
	tmp = rcu_dereference_protected(orig->replacedby->profile,
					mutex_is_locked(&orig->ns->lock));
	rcu_assign_pointer(orig->replacedby->profile, pyr_get_profile(new));
	orig->flags |= PFLAG_INVALID;
	pyr_put_profile(tmp);
}

/**
 * pyr_get_namespace - increment references count on @ns
 * @ns: namespace to increment reference count of (MAYBE NULL)
 *
 * Returns: pointer to @ns, if @ns is NULL returns NULL
 * Requires: @ns must be held with valid refcount when called
 */
static inline struct pyr_namespace *pyr_get_namespace(struct pyr_namespace *ns)
{
	if (ns)
		pyr_get_profile(ns->unconfined);

	return ns;
}

/**
 * pyr_put_namespace - decrement refcount on @ns
 * @ns: namespace to put reference of
 *
 * Decrement reference count of @ns and if no longer in use free it
 */
static inline void pyr_put_namespace(struct pyr_namespace *ns)
{
	if (ns)
		pyr_put_profile(ns->unconfined);
}

static inline int AUDIT_MODE(struct pyr_profile *profile)
{
	if (pyr_g_audit != AUDIT_NORMAL)
		return pyr_g_audit;

	return profile->audit;
}

bool pyr_policy_view_capable(void);
bool pyr_policy_admin_capable(void);
bool pyr_may_manage_policy(int op);

#endif /* __PYR_POLICY_H */
