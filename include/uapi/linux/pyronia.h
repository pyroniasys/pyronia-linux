/*
 * Pyronia security module
 *
 * This file contains the Pyronia callgraph definitions.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_MAC_H
#define __PYR_MAC_H

#include <crypto/sha.h>

#define CALLSTACK_STR_DELIM ","
#define SI_PORT_STR_DELIM ":"
#define LIB_RULE_STR_DELIM ","
#define RESOURCE_STR_DELIM " "
#define DEFAULT_NAME "d"

struct pyr_userspace_stack_hash {
    union {
        char *filename;
        struct sockaddr *addr;
    } resource;
    int includes_stack;
    unsigned char hash[SHA256_DIGEST_SIZE];
};

#endif /* __PYR_MAC_H */
