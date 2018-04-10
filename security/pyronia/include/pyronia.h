/*
 * AppArmor security module
 *
 * This file contains AppArmor basic global and lib definitions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYRONIA_H
#define __PYRONIA_H

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include "match.h"

// msm: comment this out if we're not testing
#define PYR_TESTING 1

/*
 * Class of mediation types in the AppArmor policy db
 */
#define PYR_CLASS_ENTRY		0
#define PYR_CLASS_UNKNOWN	1
#define PYR_CLASS_FILE		2
#define PYR_CLASS_CAP		3
#define PYR_CLASS_NET		4
#define PYR_CLASS_RLIMITS	5
#define PYR_CLASS_DOMAIN		6
#define PYR_CLASS_MOUNT		7

#define PYR_CLASS_LAST		PYR_CLASS_MOUNT

/* Control parameters settable through module/boot flags */
extern enum audit_mode pyr_g_audit;
extern bool pyr_g_audit_header;
extern bool pyr_g_debug;
extern bool pyr_g_hash_policy;
extern bool pyr_g_lock_policy;
extern bool pyr_g_logsyscall;
extern bool pyr_g_paranoid_load;
extern unsigned int pyr_g_path_max;

/* Flag indicating whether initialization completed */
extern int pyronia_initialized __initdata;

/* fn's in lib */
char *pyr_split_fqname(char *args, char **ns_name);
void pyr_info_message(const char *str);
void *__pyr_kvmalloc(size_t size, gfp_t flags);

/*
 * DEBUG remains global (no per profile flag) since it is mostly used in sysctl
 * which is not related to profile accesses.
 */

#define PYR_DEBUG(fmt, args...)						\
	do {								\
	  if (pyr_g_debug && printk_ratelimit())			\
	    printk(KERN_DEBUG "Pyronia: " fmt, ##args);			\
	} while (0)
#define PYR_ERROR(fmt, args...)						\
	do {								\
	  printk(KERN_ERR "Pyronia: " fmt, ##args);			\
        } while (0)

static inline void *kvmalloc(size_t size)
{
	return __pyr_kvmalloc(size, 0);
}

static inline void *kvzalloc(size_t size)
{
	return __pyr_kvmalloc(size, __GFP_ZERO);

}

/* returns 0 if kref not incremented */
static inline int kref_get_not0(struct kref *kref)
{
	return atomic_inc_not_zero(&kref->refcount);
}

/**
 * pyr_strneq - compare null terminated @str to a non null terminated substring
 * @str: a null terminated string
 * @sub: a substring, not necessarily null terminated
 * @len: length of @sub to compare
 *
 * The @str string must be full consumed for this to be considered a match
 */
static inline bool pyr_strneq(const char *str, const char *sub, int len)
{
	return !strncmp(str, sub, len) && !str[len];
}

/**
 * pyr_dfa_null_transition - step to next state after null character
 * @dfa: the dfa to match against
 * @start: the state of the dfa to start matching in
 *
 * pyr_dfa_null_transition transitions to the next state after a null
 * character which is not used in standard matching and is only
 * used to separate pairs.
 */
static inline unsigned int pyr_dfa_null_transition(struct pyr_dfa *dfa,
						  unsigned int start)
{
	/* the null transition only needs the string's null terminator byte */
	return pyr_dfa_next(dfa, start, 0);
}

static inline bool mediated_filesystem(struct dentry *dentry)
{
	return !(dentry->d_sb->s_flags & MS_NOUSER);
}

/**
 * set_str - copy the src string into the dest string 
 * in a clean buffer. This is used to cleanly set the
 * string fields in the various Pyronia data structures.
 */
static inline int set_str(const char *src, char **dest) {
  char *str = NULL;
  int err = 0;
  
  // let's make sure to not override a non-null
  // destination
  if (*dest)
    return 0;

  str = kvzalloc(strlen(src)+1);
  if (!str) {
    err = -1;
    goto out;
  }

  memset(str, 0, strlen(src)+1);
  memcpy(str, src, strlen(src));
  
 out:
  *dest = str;
  return err;
}

#endif /* __PYRONIA_H */
