/*
 * Pyronia security module
 *
 * Implements the Pyronia library policy definitions.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/string.h>
#include <uapi/linux/pyronia.h>
#include <crypto/hash.h>

#include "include/pyronia.h"
#include "include/lib_policy.h"
#include "include/policy.h"

enum regex_type {
	MATCH_FULL = 0,
	MATCH_FRONT_ONLY,
	MATCH_MIDDLE_ONLY,
	MATCH_END_ONLY,
};

// Recursively free the lib policies
static void free_lib_policy(struct pyr_lib_policy **policy) {
    struct pyr_lib_policy *p = *policy;

    if (p == NULL) {
      return;
    }
        
    if (p->next != NULL) {
      free_lib_policy(&p->next);
    }

    kvfree(p->lib_name);
    kvfree(p);
    *policy = NULL;
}

// Recursively free the ACL entries
static void free_acl_entry(struct pyr_acl_entry **entry) {
    struct pyr_acl_entry *e = *entry;
    int i = 0;

    if (e == NULL) {
      return;
    }

    if (e->next != NULL) {
      free_acl_entry(&e->next);
    }

    free_lib_policy(&e->auth_libs);
    e->num_logged_hashes = 0;
    for (i = 0; i < MAX_LOGGED_HASHES; i++) {
        memset(e->logged_stack_hashes[i].h, 0, SHA256_DIGEST_SIZE);
        e->logged_stack_hashes[i].perms = 0;
    }
    if (e->resource)
        kvfree(e->resource);
    
    kvfree(e);    
    *entry = NULL;
}

// Allocates a new ACL entry and adds it to the ACL pointed to by `acl`.
// This function can also be used to initialize `acl`.
// The new entry will be pointed to by `acl` when this function returns.
// Returns 0 on success, -1 on failure
static int pyr_add_acl_entry(struct pyr_acl_entry **acl,
                      enum acl_entry_type entry_type,
                      const char *name) {
    struct pyr_acl_entry *new_entry = kvzalloc(sizeof(struct pyr_acl_entry));
    int i = 0;
    int err = -1;
    
    if (new_entry == NULL) {
        printk(KERN_ERR "[%s] NO MEM for new ACL entry for %s\n", __func__, name);
        goto fail;
    }

    new_entry->entry_type = entry_type;
    if (set_str(name, &new_entry->resource)) {
        printk(KERN_CRIT "[%s] Could not set resource for ACL %s\n", __func__, name);
        goto fail;
    }
    new_entry->auth_libs = NULL;
    new_entry->num_logged_hashes = 0;
    for (i = 0; i < MAX_LOGGED_HASHES; i++) {
        memset(new_entry->logged_stack_hashes[i].h, 0, SHA256_DIGEST_SIZE);
        new_entry->logged_stack_hashes[i].perms = 0;
    }
    
    // TODO: track data types
    new_entry->data_type = 0;
    // insert at head of linked list
    new_entry->next = *acl;

    PYR_DEBUG(KERN_ERR "[%s] Added ACL entry %p for %s\n", __func__, new_entry, name);
    
    err = 0;
    goto out;
 fail:
    if (new_entry)
        free_acl_entry(&new_entry);
 out:
    *acl = new_entry;
    return err;
}

/**
 * parse_regex - parse a basic regex
 * @buff:   the raw regex
 * @len:    length of the regex
 * @search: will point to the beginning of the string to compare
 * @offset: the character at which the matching needs to be resumed
 *
 * This passes in a buffer containing a regex and this function will
 * set search to point to the search part of the buffer and
 * return the type of search it is (see enum above).
 * This does modify buff.
 *
 * Returns enum type.
 *  search returns the pointer to use for comparison.
 *  not returns 1 if buff started with a '!'
 *     0 otherwise.
 */
static enum regex_type parse_regex(char *buf, int len, int *search, char **offset) {
	int type = MATCH_FULL;
	int i;
	*offset = NULL;
	*search = 0;
	
	for (i = 0; i < len; i++) {
	  if (buf[i] == '*') {
	    if (!i) {
	      type = MATCH_END_ONLY;
	      i++;
	      while(buf[i] == '*') {
		i++;
	      }
	      *offset = buf+i;
	    }
	    else {
	      type = MATCH_FRONT_ONLY;
	      *search = i;
	      i++;
	      while(buf[i] == '*') {
		i++;
	      }
	      // this is the other half of the string we need to match
	      *offset = buf+i;
	      break;
	    }
	  }
	}

	return type;
}

static int name_regex_match(char *acl_name, const char *to_match) {
  int matched = 0;
  int search = 0;
  int type = 0;
  char *offset = NULL;
  int cmp_len = 0;

  if (!acl_name)
    return 0;

  if (!to_match)
    return 0;
  
  type = parse_regex(acl_name, strlen(acl_name), &search,
		     &offset);

  size_t acl_name_len = strlen(acl_name);
  size_t to_match_len = strlen(to_match);
  
  switch (type) {
  case MATCH_FULL:
    if (strncmp(to_match, acl_name, (acl_name_len >= to_match_len ? acl_name_len : to_match_len)) == 0)
      matched = 1;
    break;
  case MATCH_FRONT_ONLY:
    if (strncmp(to_match, acl_name, search) == 0) {
      if (offset == NULL)
	matched = 1;
      else {
	cmp_len = strlen(to_match);
	if (strncmp(to_match + (cmp_len-strlen(offset)), offset, strlen(offset)) == 0) {
	  matched = 1;
	}
      }
    }
    break;
  case MATCH_END_ONLY:
    cmp_len = strlen(to_match);
    if (offset && cmp_len >= strlen(offset) &&
	memcmp(to_match + (cmp_len - strlen(offset)), offset, strlen(offset)) == 0)
      matched = 1;
    break;
  }

  if (matched)
    PYR_DEBUG("[%s] Match ACL entry %s with name %s (match type %d)\n", __func__, acl_name, to_match, type);

  return matched;
}

// Finds the ACL entry for `name` in the given linked list `start`.
// Returns null if no entry for `name` exists.
struct pyr_acl_entry *pyr_find_acl_entry(struct pyr_acl_entry *start,                                                 const char *name) {

    // traverse the ACL entry linked list, start at the head
    struct pyr_acl_entry *runner = start;

    PYR_DEBUG(KERN_ERR "[%s] Searching for ACL %s\n", __func__, name);

    while (runner != NULL) {
        // we have two types of entries, so need to check the type
        // on each before we determine if we've found the requested ACL entry
        if (name_regex_match(runner->resource, name)) {
                return runner;
        }
        
        runner = runner->next;
    }

    // if we get here, we don't have an ACL entry for this name
    // (resource or net destination)
    return NULL;
}

// Finds the lib policy for `lib` in the policy DB given by `policy_db`.
// Returns null if no entry for `lib` exists.
static struct pyr_lib_policy * pyr_find_lib_policy(struct pyr_acl_entry *acl, const char *lib) {

    // traverse the policy linked list, start at the head
    struct pyr_lib_policy *runner = acl->auth_libs;

    PYR_DEBUG(KERN_ERR "[%s] Searching for lib policy %s for ACL %s\n", __func__, lib, acl->resource);

    while (runner != NULL) {
        if (!strncmp(runner->lib_name, lib, strlen(runner->lib_name))) {
	  PYR_DEBUG("[%s] Found policy for library %s\n", __func__, runner->lib_name);
	  return runner;
        }
        runner = runner->next;
    }

    // if we get here, we don't have a policy for this library
    return NULL;
}

// Returns the allowed permissions or operations for the given library
// associated with the given ACL entry
u32 pyr_get_lib_perms(struct pyr_acl_entry *acl, const char *lib) {
    struct pyr_lib_policy *auth_lib = NULL;

    auth_lib = pyr_find_lib_policy(acl, lib);
    if (auth_lib == NULL)
        return TRANSITIVE_LIB_POLICY;

    else
        return auth_lib->perms;
}

// Allocates a new library policy and adds it to the policy DB pointed to
// by `policy_db`.
// This function can be used to initialize `policy_db`, but it *cannot* be
// used to allocate `policy_db`.
// The new policy will be pointed to by `policy_db->perm_db_head` when
// this function returns.
// Returns 0 on success, -1 on failure
int pyr_add_lib_policy(struct pyr_lib_policy_db *policy_db,
                       const char *lib, enum acl_entry_type entry_type,
                       const char *name, u32 perms) {

    struct pyr_lib_policy *policy = NULL;
    struct pyr_acl_entry *acl = NULL;

    if (!policy_db) {
      printk(KERN_CRIT "[%s] Oops, no policy DB\n", __func__);
      goto fail;
    }
    
    acl = pyr_find_acl_entry(policy_db->lib_policies, name);
    if (!acl) {
        if (pyr_add_acl_entry(&policy_db->lib_policies, entry_type, name)) {
	  printk(KERN_CRIT "[%s] Could not add new ACL entry for %s\n", __func__, name);
            goto fail;
        }
	acl = policy_db->lib_policies;
    }
    else {
        // There can only be one type of ACL entry per resource, so
        // ignore the new perms if the entry types conflict, but don't
        // throw an error
        if (acl->entry_type != entry_type) {
	  printk(KERN_CRIT "[%s] Oops, attempting to modify the entry type for %s\n", __func__, name);
	  goto out;
        }
    }
    
    policy = pyr_find_lib_policy(acl, lib);
    if (!policy) {
        policy = kvzalloc(sizeof(struct pyr_lib_policy));
        if (!policy) {
	    printk(KERN_CRIT "[%s] no mem for %s policy\n", __func__, lib);
            goto fail;
        }
	if (set_str(lib, &policy->lib_name))
	  goto fail;
        policy->perms = perms;

        // insert at head of linked list
	policy->next = acl->auth_libs;
        acl->auth_libs = policy;
    }

    PYR_DEBUG("[%s] Added policy %p for %s, next %p\n", __func__, policy_db->lib_policies, lib, policy_db->lib_policies->next);

 out:
    return 0;
 fail:
    free_acl_entry(&acl);
    return -1;
}

// Allocates a new default policy entry and adds it to the policy DB
// pointed to by `policy_db`.
// This function can be used to initialize `policy_db`, but it *cannot* be
// used to allocate `policy_db`.
// The new policy will be pointed to by `policy_db->defaults` when
// this function returns.
// Returns 0 on success, -1 on failure
int pyr_add_default(struct pyr_lib_policy_db *policy_db,
                    enum acl_entry_type entry_type, const char *name) {
    struct pyr_acl_entry *acl = NULL;

    acl = pyr_find_acl_entry(policy_db->defaults, name);
    if (!acl) {
        if (pyr_add_acl_entry(&policy_db->defaults, entry_type, name)) {
            goto fail;
        }
    }
    else {
        // There can only be one type of ACL entry per resource, so
        // ignore the new perms if the entry types conflict, but don't
        // throw an error
        if (policy_db->defaults->entry_type != entry_type) {
            goto out;
        }
    }

 out:
    return 0;
 fail:
    return -1;
}

int pyr_is_default_lib_policy(struct pyr_lib_policy_db *lib_policy_db,
                              const char *name) {
    struct pyr_acl_entry *acl = NULL;
    int is_def = 0;

    acl = pyr_find_acl_entry(lib_policy_db->defaults, name);

    // we don't have an entry in our ACL for this `name`,
    // so check the lib policy DB
    if (acl != NULL) {
        is_def = 1;
    }

    return is_def;
}

// Allocates a new policy DB
// Returns 0 on success, -1 on failure
int pyr_new_lib_policy_db(struct pyr_lib_policy_db **policy_db) {
    struct pyr_lib_policy_db *db = kvzalloc(sizeof(struct pyr_lib_policy_db));

    if (db == NULL) {
        goto fail;
    }

    db->lib_policies = NULL;
    db->defaults = NULL;
    *policy_db = db;

    init_stack_logging_hash();

    return 0;
 fail:
    kvfree(db);
    return -1;
}

// Free a lib policy DB
// Recursively frees all lib policies and their ACL entries
void pyr_free_lib_policy_db(struct pyr_lib_policy_db **policy_db) {
    struct pyr_lib_policy_db *db = *policy_db;
    
    if (db == NULL)
      return;

    free_acl_entry(&db->lib_policies);
    free_acl_entry(&db->defaults);
    kvfree(db);
    *policy_db = NULL;
}

// Deserialize a lib policy string received from userspace
// profile is NOT NULL
int pyr_deserialize_lib_policy(struct pyr_profile *profile,
                               char *lp_str) {
    int err = 0;
    char *next_rule, *num_str, *next_lib, *next_name;
    u32 num_rules = 0, next_perms = 0, count = 0;
    enum acl_entry_type next_type;
    
    // first token in the string is the number of lib policy
    // rules to expect
    num_str = strsep(&lp_str, LIB_RULE_STR_DELIM);

    err = kstrtou32(num_str, 10, &num_rules);
    if (err) {
        PYR_ERROR("[%s] Malformed num rules %s\n", __func__,
		  num_str);
        goto fail;
    }

    PYR_DEBUG("[%s] Num of rules %d\n", __func__, num_rules);
    
    next_rule = strsep(&lp_str, LIB_RULE_STR_DELIM);
    while(next_rule && count < num_rules) {
        next_lib = strsep(&next_rule, RESOURCE_STR_DELIM);
        if (!next_lib) {
            PYR_ERROR("[%s] Malformed lib in policy rule %s\n", __func__,
                      next_rule);
            goto fail;
        }

        // let's check if this is a resource entry or network entry:
        // network entries are going to have an extra "resource" section
        if(!strncmp(next_rule, "network ", 8)) {
            next_type = net_entry;
            next_rule = next_rule+8;
            next_perms = OP_CONNECT | OP_BIND; // FIXME: policy should specify
        }
        else {
            next_type = resource_entry;
        }

        next_name = strsep(&next_rule, LIB_RULE_STR_DELIM);
        if (!next_name) {
            PYR_ERROR("[%s] Malformed name in policy rule %s\n", __func__,
                      next_rule);
            goto fail;
        }

        // compute the perms for this resource from the file DFA
        // in the profile since this rule is a resource rule
        if (next_type == resource_entry) {
            next_perms = pyr_get_allow_file_perms(profile, next_name);
        }

        // now let's add the appropriate ACL entry: either default
        // or library
        if (!strncmp(next_lib, DEFAULT_NAME, 1)) {
            err = pyr_add_default(profile->lib_perm_db, next_type,
                                  next_name);
        }
        else {
            err = pyr_add_lib_policy(profile->lib_perm_db, next_lib,
                                     next_type, next_name, next_perms);
        }
        if (err) {
	  PYR_ERROR("[%s] Could not add new ACL entry\n", __func__);
            goto fail;
        }

	count++;
	if (lp_str)
	  next_rule = strsep(&lp_str, LIB_RULE_STR_DELIM);
    }

    // the string was somehow corrupted b/c we got fewer valid rules than
    // originally indicated
    if (num_rules > 0 && count < num_rules) {
        PYR_ERROR("[%s] Expected %d, got %d rules\n", __func__, num_rules, count);
	err = -1;
        goto fail;
    }

    return 0;
 fail:
    return err;
}
