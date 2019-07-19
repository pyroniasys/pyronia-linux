/*
 * Pyronia security module
 *
 * This file contains Pyronia library policy definitions.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_LIBPOLICY_H
#define __PYR_LIBPOLICY_H

#include <linux/types.h>
#include "stack_logging.h"

/* This is used to indicate to the stack inspector
 * that a library's permissions should be transitively
 * passed on to the next library in a callstack.
 */
#define TRANSITIVE_LIB_POLICY 0xffffffff

/* pyr_lib_perms defines the possible permissions a library can
 * have under Pyronia
 */
enum pyr_lib_perms {
    CAM_PERM, // read-only access to the camera
    MIC_PERM, // read-only access to the microphone
    ENV_SENSOR_PERM, // read-only access to a specified environmental sensor
    CRED_PERM, // read-only access to specified credentials
    FILE_R_PERM, // read access from a specified file
    FILE_W_PERM, // write access to a specified file
    NET_R_PERM, // read access from a specified net addr
    // write access of a specified data type to a specified net addr
    NET_W_PERM,
    EXEC_PERM, //exec access of a specified binary
};

/** pyr_data_types defines the possible expected sensitive
 * data types obtained from sensors or files
 */
enum pyr_data_types {
    CAM_DATA,
    MIC_DATA,
    ENV_DATA,
    MISC_FILE_DATA,
    // TODO: add more fine-grained types
};

struct path;

// indicates whether a library ACL entry
// is for a local resource
// or a remote network destination
enum acl_entry_type {
    resource_entry,
    net_entry,
};

// the permissions given to a specific library
// to a resource/network
struct pyr_lib_policy {
    char *lib_name;
    // this is the OR of various file access permissions
    // need to match with requested & ~perms to allow
    u32 perms;
    struct pyr_lib_policy *next;
};

// this is an individual entry in the ACL for
// a library
struct pyr_acl_entry {

    enum acl_entry_type entry_type;
    char *resource;

    struct pyr_lib_policy *auth_libs;
    int num_logged_hashes;
    stack_hash_t logged_stack_hashes[MAX_LOGGED_HASHES];

    // TODO: currently unused
    enum pyr_data_types data_type;
    struct pyr_acl_entry *next;
};

/* An application's Pyronia library policy database.
 * policy_db_head: The first entry in the policy database
 *      linked list
 * defaults: The list of resource entries that can be accessed
 *      by all libraries so long as the requested access matches
 */
struct pyr_lib_policy_db {
    struct pyr_acl_entry *lib_policies;
    struct pyr_acl_entry *defaults;
};

int pyr_add_lib_policy(struct pyr_lib_policy_db *, const char *,
                       enum acl_entry_type, const char *, u32);
int pyr_add_default(struct pyr_lib_policy_db *, enum acl_entry_type,
                    const char *);
struct pyr_acl_entry *pyr_find_acl_entry(struct pyr_acl_entry *,                                                 const char *);
u32 pyr_get_lib_perms(struct pyr_acl_entry *, const char *);
int pyr_is_default_lib_policy(struct pyr_lib_policy_db *, const char *);
int pyr_new_lib_policy_db(struct pyr_lib_policy_db **);
void pyr_free_lib_policy_db(struct pyr_lib_policy_db **);

struct pyr_profile;
int pyr_deserialize_lib_policy(struct pyr_profile *profile,
                               char *lp_str);

#endif /* __PYR_LIBPOLICY_H */
