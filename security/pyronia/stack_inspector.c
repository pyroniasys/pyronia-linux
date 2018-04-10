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

#include "include/pyronia.h"
#include "include/stack_inspector.h"
#include "include/si_comm.h"
#include "include/callgraph.h"
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
  
  pyr_cg_node_t *callgraph = NULL;
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
    PYR_ERROR("[%s] Could not get callstack from runtime for library %s for runtime %d\n", __func__, name, port_id);
    goto out;
  }

  // compute the effective permissions given the callstack and
  // recorded library permissions
  if (pyr_compute_lib_perms(lib_perm_db, callgraph, name, &perms)) {
    PYR_ERROR("[%s] Error inspecting stack for library %s for runtime %d\n", __func__, name, port_id);
  }

 out:
  pyr_free_callgraph(&callgraph);
  *lib_perms = perms;
}
