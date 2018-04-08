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

#include <linux/kernel.h>
#include <linux/string.h>

#include "include/callgraph.h"
#include "include/pyronia.h"

// Allocate a new callgraph node
int pyr_new_cg_node(pyr_cg_node_t **cg_root, const char* lib,
                        enum pyr_data_types data_type,
                        pyr_cg_node_t *child) {

    pyr_cg_node_t *n = (pyr_cg_node_t *)kvzalloc(sizeof(pyr_cg_node_t));

    if (n == NULL) {
        goto fail;
    }

    n->lib = kvzalloc(strlen(lib)+1);
    memcpy(n->lib, lib, strlen(lib));
    n->data_type = data_type;
    n->child = child;

    *cg_root = n;
    return 0;
 fail:
    kvfree(n);
    return -1;
}

// Traverse the given callgraph computing each module's permissions
// at each frame, and return the effective permission
int pyr_compute_lib_perms(struct pyr_lib_policy_db *lib_policy_db,
                     pyr_cg_node_t * callgraph, const char *name,
                     u32 *perms) {

    pyr_cg_node_t *cur_node = callgraph;
    int err = 0;
    u32 eff_perm = 0;

    PYR_DEBUG("Callgraph - Computing permissions for %s... \n", name);

    eff_perm = pyr_get_lib_perms(lib_policy_db, cur_node->lib, name);

    PYR_DEBUG("Callgraph - Initial permissions for %s: %d\n", name, eff_perm);

    // a return value of TRANSITIVE_LIB_POLICY from pyr_get_lib_perms
    // means that we don't have a policy for the library.
    // In this initial call, it means the root already doesn't have
    // permission to access name, so let's bail early
    if (eff_perm == TRANSITIVE_LIB_POLICY) {
        goto out;
    }

    cur_node = callgraph->child;
    while (cur_node != NULL) {
        // take the intersection of the permissions
        eff_perm &= pyr_get_lib_perms(lib_policy_db, cur_node->lib, name);

        PYR_DEBUG("Callgraph - Current effective permissions for %s: %d\n", name, eff_perm);

        // bail early since the callgraph so far already doesn't have
        // access to `name`
        if (eff_perm == 0) {
            goto out;
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
        kvfree(n->lib);
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

// Deserialize a callstack-string received from userspace
int pyr_deserialize_callstack(pyr_cg_node_t **root, char *cs_str) {
    pyr_cg_node_t *cur_node = NULL, *next_node = NULL;
    int err;
    char *next_lib, *num_str;
    u32 num_nodes, count = 0;

    // first token in the string is the number of callstack
    // layers to expect
    num_str = strsep(&cs_str, CALLSTACK_STR_DELIM);

    err = kstrtou32(num_str, 10, &num_nodes);
    if (err)
        goto fail;

    next_lib = strsep(&cs_str, CALLSTACK_STR_DELIM);
    while(next_lib && count < num_nodes) {
        err = pyr_new_cg_node(&next_node, next_lib, 0, NULL);
        if (err) {
            goto fail;
        }
        // the string we receive is ordered from CG root to leaf
        // so we need to re-assign the last node's child to the new node
        // before the next iteration
        if (cur_node == NULL) {
          cur_node = next_node;
          *root = cur_node;
        }
        else{
          cur_node->child = next_node;
          cur_node = cur_node->child;
        }
        next_node = NULL;

        next_lib = strsep(&cs_str, CALLSTACK_STR_DELIM);
        count++;
    }

    // the string was somehow corrupted b/c we got fewer valid nodes than
    // originally indicated
    if (num_nodes > 0 && count < num_nodes)
        goto fail;

    return 0;
 fail:
    if (next_node)
        pyr_free_callgraph(&next_node);
    if (cur_node)
        pyr_free_callgraph(&cur_node);
    if (*root)
        pyr_free_callgraph(root);

    *root = NULL;
    return err;
}
