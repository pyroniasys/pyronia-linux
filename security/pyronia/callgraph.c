/*
 * Pyronia security module
 *
 * Implements the Pyronia callgraph interface.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "include/callgraph.h"

#ifdef PYR_TESTING
#if PYR_TESTING
#include "include/kernel_test.h"
#else
#include "include/userland_test.h"
#endif
#else
#include "include/pyronia.h"
#endif

// Allocate a new callgraph node
int pyr_new_cg_node(pyr_cg_node_t **cg_root, const char* lib,
                        enum pyr_data_types data_type,
                        pyr_cg_node_t *child) {

    pyr_cg_node_t *n = (pyr_cg_node_t *)kvzalloc(sizeof(pyr_cg_node_t));

    if (n == NULL) {
        goto fail;
    }

    n->lib = lib;
    n->data_type = data_type;
    n->child = child;

    *cg_root = n;
    return 0;
 fail:
    kvfree(n);
    return -1;
}

// Gets the permissions for the given resource from the library's policy
static u32 get_perms_for_name(struct pyr_lib_policy * policy,
                              const char *name) {

    struct pyr_acl_entry *acl = pyr_find_lib_acl_entry(policy, name);

    // we don't have an entry in our ACL for this `name`,
    // so the library doesn't have any permissions to access `name`.
    // default-deny policy
    if (acl == NULL) {
        return 0;
    }

    return pyr_get_perms_from_acl(acl);
}

// Traverse the given callgraph computing each module's permissions
// at each frame, and return the effective permission
int pyr_compute_lib_perms(struct pyr_lib_policy_db *lib_policy_db,
                     pyr_cg_node_t * callgraph, const char *name,
                     u32 *perms) {
  
    pyr_cg_node_t *cur_node = callgraph;
    int err = 0;
    u32 eff_perm = 0;
    struct pyr_lib_policy *cur_policy;

#ifdef PYR_TESTING
    PYR_DEBUG("Callgraph - Computing permissions for %s... \n", name);
#endif
    
    // want effective permission to start as root library in callgraph
    cur_policy = pyr_find_lib_policy(lib_policy_db, cur_node->lib);

    // something seriously went wrong if we don't have the root lib
    // in our policy DB
    if (cur_policy == NULL) {
        // TODO: throw some big error here
        err = -1;
        goto out;
    }

    eff_perm = get_perms_for_name(cur_policy, name);

#ifdef PYR_TESTING
    PYR_DEBUG("Callgraph - Initial permissions for %s: %d\n", name, eff_perm);
#endif

    // bail early since the root already doesn't have permission
    // to access name
    if (eff_perm == 0) {
        goto out;
    }

    cur_node = callgraph->child;
    while (cur_node != NULL) {
        cur_policy = pyr_find_lib_policy(lib_policy_db, cur_node->lib);

        // if we don't have an explicit policy for this library,
        // inherit the current effective permissions, otherwise adjust
        if (cur_policy != NULL) {
            // take the intersection of the permissions
            eff_perm &= get_perms_for_name(cur_policy, name);


#ifdef PYR_TESTING
	    PYR_DEBUG("Callgraph - Current effective permissions for %s: %d\n", name, eff_perm);
#endif

            // bail early since the callgraph so far already doesn't have
            // access to `name`
            if (eff_perm == 0) {
                goto out;
            }
        }

        cur_node = cur_node->child;
    }

 out:
    *perms = eff_perm;
    return err;
}

// Recursively free the callgraph nodes
static void free_node(pyr_cg_node_t **node) {
    pyr_cg_node_t *n = *node;

    if (n == NULL) {
      return;
    }
    
    if (n->child == NULL) {
        n->lib = NULL;
        kvfree(n);
    }
    else {
        free_node(&(n->child));
    }
    *node = NULL;
}

// Free a callgraph
void pyr_free_callgraph(pyr_cg_node_t **cg_root) {
    free_node(cg_root);
}
