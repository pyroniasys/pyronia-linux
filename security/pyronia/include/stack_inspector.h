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

struct pyr_cg_node;
typedef struct pyr_cg_node pyr_cg_node_t;

// FIXME: support multi-threaded programs (see: https://github.com/flexdroid/dalvik/blob/domain/vm/remote_stack_inspector/main.cpp#L172)
void request_callstack(pyr_cg_node_t **);

#endif /* __PYR_STACK_INSP_H */
