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

#include <uapi/linux/pyronia.h>

#include "include/pyronia.h"
#include "include/stack_inspector.h"
#include "include/si_comm.h"
#include "include/lib_policy.h"

int pyr_callstack_request_alloc(struct pyr_callstack_request **req) {  
  struct pyr_callstack_request *r = kvzalloc(sizeof(struct pyr_callstack_request));
  
  if (r == NULL) {
    goto fail;
  }
  
  r->port_id = 0;
  r->runtime_responded = 0;
  memset(r->cg_buf, 0, MAX_RECV_LEN);
  mutex_init(&r->req_mutex);
  
  *req = r;
  return 0;
 fail:
  kvfree(r);
  return -1;
}

void pyr_callstack_request_free(struct pyr_callstack_request **crp) {
  struct pyr_callstack_request *r = *crp;
  
  if (r == NULL) {
    return;
  }

  memset(r->cg_buf, 0, MAX_RECV_LEN);
  r->port_id = 0;
  r->runtime_responded = 0;

  kvfree(r);
  *crp = NULL;
}

// Deserialize a callstack-string received from userspace and
// compute each parsed module's permissions
// at each frame, and return the effective permission
static int pyr_compute_lib_perms(struct pyr_lib_policy_db *lib_policy_db,
                     char *callgraph, const char *name,
                     u32 *perms) {

    int err = 0;
    u32 eff_perm = TRANSITIVE_LIB_POLICY;
    char *cur_lib = NULL, *num_str = NULL;
    u32 num_nodes = 0, count = 0;

    PYR_DEBUG(KERN_CRIT "[%s] Callstack: %s\n", __func__, callgraph);
    
    // first token in the string is the number of callstack
    // layers to expect
    num_str = strsep(&callgraph, CALLSTACK_STR_DELIM);

    err = kstrtou32(num_str, 10, &num_nodes);
    if (err)
        goto out;

    cur_lib = strsep(&callgraph, CALLSTACK_STR_DELIM);
    while(cur_lib && count < num_nodes) {

        PYR_DEBUG("[%s] Computing permissions for %s... \n", __func__, name);

        // take the intersection of the permissions
        eff_perm &= pyr_get_lib_perms(lib_policy_db, cur_lib, name);

        // a return value of TRANSITIVE_LIB_POLICY from pyr_get_lib_perms
        // means that we don't have a policy for the library.
        // In this initial call, it means the root already doesn't have
        // permission to access name, so let's bail early
        if (count == 0 && eff_perm == TRANSITIVE_LIB_POLICY) {
            eff_perm = 0;
            goto out;
        }
        // bail early since the callgraph so far already doesn't have
        // access to `name`
        else if (eff_perm == 0) {
            goto out;
        }

        cur_lib = strsep(&callgraph, CALLSTACK_STR_DELIM);
        count++;
    }

    // the string was somehow corrupted b/c we got fewer valid nodes than
    // originally indicated
    if (num_nodes > 0 && count < num_nodes)
        eff_perm = 0;

 out:
    *perms = eff_perm;
    return err;
}

/**
 * inspect_callstack - find the library permission that matches @name
 * @port_id: the runtime identifier from which to request the callstack
 * @lib_perm_db: library permissions DB to search in
 * @name: string to match in the library permissions DB  (NOT NULL)
 * @lib_perms: Returns - the effective permissions computed from the callgraph @name
 *
 * @lib_perms is set to 0 if computing the permissions fails
 */
void pyr_inspect_callstack(u32 port_id, struct pyr_lib_policy_db *lib_perm_db,
			   const char *name, u32 *lib_perms) {
  
  char *callgraph = NULL;
  u32 perms = 0;
  struct pyr_callstack_request *req;
  
  // upcall to language runtime for callstack
  req = pyr_get_current_callstack_request();
  if (!req) {
    PYR_ERROR("[%s] Null callstack_request metadata struct\n", __func__);
    goto out;
  }
  
  mutex_lock(&req->req_mutex);
  callgraph = pyr_stack_request(port_id);
  mutex_unlock(&req->req_mutex);
  if (!callgraph) {
    PYR_ERROR("[%s] Could not get callstack from runtime for resource %s for runtime %d\n", __func__, name, port_id);
    goto out;
  }

  // compute the effective permissions given the callstack and
  // recorded library permissions
  if (pyr_compute_lib_perms(lib_perm_db, callgraph, name, &perms)) {
    PYR_ERROR("[%s] Error inspecting stack for resource %s for runtime %d\n", __func__, name, port_id);
  }

 out:
  if (callgraph)
      kvfree(callgraph);
  *lib_perms = perms;
}
