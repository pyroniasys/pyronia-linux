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

#include "include/pyronia.h"
#include "include/lib_policy.h"
#include "include/policy.h"

// Recursively free the ACL entries
static void free_acl_entry(struct pyr_acl_entry **entry) {
    struct pyr_acl_entry *e = *entry;

    if (e == NULL) {
      return;
    }

    if (e->next != NULL) {
      free_acl_entry(&e->next);
    }

    switch (e->entry_type) {
    case(resource_entry):
      kvfree(e->target.fs_resource.name);
      break;
    case(net_entry):
      kvfree(e->target.net_dest.name);
      break;
    default:
      // FIXME: set errno here or something
      break;
    }
    kvfree(e);    
    *entry = NULL;
}

// Recursively free the lib policies
static void free_lib_policy(struct pyr_lib_policy **policy) {
    struct pyr_lib_policy *p = *policy;

    if (p == NULL) {
      return;
    }
        
    if (p->next != NULL) {
      free_lib_policy(&p->next);
    }

    kvfree(p->lib);
    free_acl_entry(&p->acl);
    kvfree(p);
    *policy = NULL;
}

// Set the ACL entry fields accodring to the given data
static int set_acl_entry(struct pyr_acl_entry *entry,
                         enum acl_entry_type entry_type,
                         const char *name, u32 perms) {

    entry->entry_type = entry_type;
    switch(entry->entry_type) {
        case(resource_entry):
	    if (set_str(name, &entry->target.fs_resource.name))
	        goto fail;
            entry->target.fs_resource.perms = perms;
            break;
        case(net_entry):
	    if (set_str(name, &entry->target.net_dest.name))
	        goto fail;
            entry->target.net_dest.op = perms;
            break;
        default:
            PYR_ERROR("[%s] Unknown entry type: %d\n", __func__, entry->entry_type);
            goto fail;
    }
    return 0;

 fail:
    return -1;
}

// Allocates a new ACL entry and adds it to the ACL pointed to by `acl`.
// This function can also be used to initialize `acl`.
// The new entry will be pointed to by `acl` when this function returns.
// Returns 0 on success, -1 on failure
static int pyr_add_acl_entry(struct pyr_acl_entry **acl,
                      enum acl_entry_type entry_type,
                      const char *name,
                      u32 perms) {
    struct pyr_acl_entry *new_entry = kvzalloc(sizeof(struct pyr_acl_entry));

    if (new_entry == NULL) {
        goto fail;
    }

    if (set_acl_entry(new_entry, entry_type, name, perms))
        goto fail;

    // TODO: track data types
    new_entry->data_type = 0;
    // insert at head of linked list
    new_entry->next = *acl;
    *acl = new_entry;

    PYR_DEBUG("[%s] Added ACL entry %p for %s, next %p\n", __func__, *acl, name, (*acl)->next);
    
    return 0;
 fail:
    if (new_entry)
        free_acl_entry(&new_entry);
    return -1;
}

// Finds the ACL entry for `name` in the given linked list `start`.
// Returns null if no entry for `name` exists.
static struct pyr_acl_entry *pyr_find_acl_entry(struct pyr_acl_entry *start,                                                 const char *name) {

    // traverse the ACL entry linked list, start at the head
    struct pyr_acl_entry *runner = start;

    while (runner != NULL) {
        // we have two types of entries, so need to check the type
        // on each before we determine if we've found the requested ACL entry
        switch (runner->entry_type) {
        case(resource_entry):
            if (!strncmp(runner->target.fs_resource.name, name, strlen(name))) {
                return runner;
            }
            break;
        case(net_entry):
            if (!strncmp(runner->target.net_dest.name, name, strlen(name))) {
                return runner;
            }
            break;
        default:
            // FIXME: set errno here or something
            return NULL;
        }

        runner = runner->next;
    }

    // if we get here, we don't have an ACL entry for this name
    // (resource or net destination)
    return NULL;
}

// Finds the lib policy for `lib` in the policy DB given by `policy_db`.
// Returns null if no entry for `lib` exists.
static struct pyr_lib_policy * pyr_find_lib_policy(struct pyr_lib_policy_db *policy_db, const char *lib) {

    // traverse the policy linked list, start at the head
    struct pyr_lib_policy *runner = policy_db->perm_db_head;

    while (runner != NULL) {
        if (!strncmp(runner->lib, lib, strlen(lib))) {
            return runner;
        }
        runner = runner->next;
    }

    // if we get here, we don't have a policy for this library
    return NULL;
}

// Returns the allowed permissions or operations associated
// with the given ACL entry
static u32 pyr_get_perms_from_acl(struct pyr_acl_entry *acl) {
    switch (acl->entry_type) {
        case(resource_entry):
            return acl->target.fs_resource.perms;
        case(net_entry):
            return acl->target.net_dest.op;
        default:
            // FIXME: set errno here or something
            return 0;
        }
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

    struct pyr_lib_policy *policy;
    struct pyr_acl_entry *acl;

    policy = pyr_find_lib_policy(policy_db, lib);
    if (!policy) {
        policy = kvzalloc(sizeof(struct pyr_lib_policy));
        if (!policy) {
            PYR_ERROR("[%s] no mem for %s policy\n", __func__, lib);
            goto fail;
        }
	if (set_str(lib, &policy->lib))
	  goto fail;
	policy->acl = NULL;
	policy->next = NULL;

	// insert at head of linked list
	policy->next = policy_db->perm_db_head;
	policy_db->perm_db_head = policy;
    }

    acl = pyr_find_acl_entry(policy->acl, name);
    if (!acl) {
        if (pyr_add_acl_entry(&policy->acl, entry_type, name, perms)) {
            goto fail;
        }
    }
    else {
        // There can only be one type of ACL entry per resource, so
        // ignore the new perms if the entry types conflict, but don't
        // throw an error
        if (policy->acl->entry_type != entry_type) {
	  PYR_ERROR("[%s] Oops, attempting to modify the entry type for %s\n", __func__, name);
	  goto out;
        }

	PYR_DEBUG("[%s] Changing ACL entry for %s\n", __func__, name);
        if (set_acl_entry(policy->acl, entry_type, name, perms))
            goto fail;
    }

    PYR_DEBUG("[%s] Added policy %p for %s, next %p\n", __func__, policy_db->perm_db_head, lib, policy_db->perm_db_head->next);

    
 out:
    return 0;
 fail:
    free_lib_policy(&policy);
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
                    enum acl_entry_type entry_type, const char *name,
                    u32 perms) {
    struct pyr_acl_entry *acl;

    acl = pyr_find_acl_entry(policy_db->defaults, name);
    if (!acl) {
        if (pyr_add_acl_entry(&policy_db->defaults, entry_type, name, perms)) {
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

        if (set_acl_entry(policy_db->defaults, entry_type, name, perms))
            goto fail;
    }

 out:
    return 0;
 fail:
    return -1;
}

// Gets the permissions for the given resource from the library's policy
u32 pyr_get_lib_perms(struct pyr_lib_policy_db *lib_policy_db,
                      const char *lib, const char *name) {
    struct pyr_lib_policy *policy;
    struct pyr_acl_entry *acl;

    if (!lib_policy_db)
      return 0;
    
    // we don't have a policy for this `lib`, so
    // uphold our default-deny policy
    policy = pyr_find_lib_policy(lib_policy_db, lib);

    // if we don't have an explicit policy for this library,
    // we use transitive effective permissions
    if (!policy) {
        return TRANSITIVE_LIB_POLICY;
    }

    acl = pyr_find_acl_entry(policy->acl, name);

    // we don't have an entry in our ACL for this `name`,
    // so the library doesn't have any permissions to access `name`.
    // default-deny policy
    if (acl == NULL) {
        return 0;
    }

    return pyr_get_perms_from_acl(acl);
}

// Gets the permissions for the given default resource from the policy DB
u32 pyr_get_default_perms(struct pyr_lib_policy_db *lib_policy_db,
                          const char *name) {
    struct pyr_acl_entry *acl;

    if (!lib_policy_db)
      return 0;
    
    acl = pyr_find_acl_entry(lib_policy_db->defaults, name);

    // we don't have an entry in our ACL for this `name`,
    // so the library doesn't have any permissions to access `name`.
    // default-deny policy
    if (acl == NULL) {
        return 0;
    }

    return pyr_get_perms_from_acl(acl);
}

int pyr_is_default_lib_policy(struct pyr_lib_policy_db *lib_policy_db,
                           const char *name) {
    struct pyr_acl_entry *acl;

    acl = pyr_find_acl_entry(lib_policy_db->defaults, name);

    // we don't have an entry in our ACL for this `name`,
    // so the library doesn't have any permissions to access `name`.
    // default-deny policy
    if (acl == NULL) {
        return 0;
    }

    return 1;
}

// Allocates a new policy DB
// Returns 0 on success, -1 on failure
int pyr_new_lib_policy_db(struct pyr_lib_policy_db **policy_db) {
    struct pyr_lib_policy_db *db = kvzalloc(sizeof(struct pyr_lib_policy_db));

    if (db == NULL) {
        goto fail;
    }

    db->perm_db_head = NULL;
    db->defaults = NULL;
    *policy_db = db;

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

    free_lib_policy(&db->perm_db_head);
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
            next_perms = OP_CONNECT;
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
                                  next_name, next_perms);
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
