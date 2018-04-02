/*
 * Pyronia security module
 *
 * This file contains the Pyronia stack inspector definitions.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_STACK_INSP_H
#define __PYR_STACK_INSP_H

#include "lib_policy.h"

#define MAX_RECV_LEN 1024

struct pyr_callstack_request {
  u32 port_id;
  int runtime_responded;
  char cg_buf[MAX_RECV_LEN];
  struct mutex req_mutex;
};

int pyr_callstack_request_alloc(struct pyr_callstack_request **req);
void pyr_callstack_request_free(struct pyr_callstack_request **crp);
void pyr_inspect_callstack(u32 port_id, struct pyr_lib_policy_db *lib_perm_db,
			   const char *name, u32 *lib_perms);

#endif /* __PYR_STACK_INSP_H */
