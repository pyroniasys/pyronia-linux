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
#include <uapi/linux/pyronia_mac.h>

/* This is used to indicate to the stack inspector
 * that a library's permissions should be transitively
 * passed on to the next library in a callstack.
 */
#define TRANSITIVE_LIB_POLICY 0xffffffff

#define SI_PORT_STR_DELIM ":"
#define LIB_RULE_STR_DELIM ","
#define RESOURCE_STR_DELIM " "
#define DEFAULT_NAME "d"

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

struct path;

// indicates whether a library ACL entry
// is for a local resource
// or a remote network destination
enum acl_entry_type {
    resource_entry,
    net_entry,
};

// contains the permissions
// for a file system resource-based
// permissions
struct resource_entry {
    char *name;
    // this is the OR of various file access permissions
    // need to match with requested & ~perms to allow
    u32 perms;
};

struct net_entry {
    char *name;
    // this is the OR of various permitted network operations
    // need to match with requested_op & ~op to allow
    u32 op;
};

// this is an individual entry in the ACL for
// a library
struct pyr_acl_entry {

    enum acl_entry_type entry_type;

    union {
        struct resource_entry fs_resource;
        struct net_entry net_dest;
    } target;

    // TODO: currently unused
    enum pyr_data_types data_type;
    struct pyr_acl_entry *next;
};

/* An individual library policy for an application.
 * lib: the library this policy belongs too
 * acl: the ACL containing the library's permissions
 * next: the next entry in the library policy database
 */
struct pyr_lib_policy {
    char* lib;
    struct pyr_acl_entry *acl;
    struct pyr_lib_policy *next;
};

/* An application's Pyronia library policy database.
 * policy_db_head: The first entry in the policy database
 *      linked list
 * defaults: The list of resource entries that can be accessed
 *      by all libraries so long as the requested access matches
 */
struct pyr_lib_policy_db {
    struct pyr_lib_policy *perm_db_head;
    struct pyr_acl_entry *defaults;
};

int pyr_add_lib_policy(struct pyr_lib_policy_db *, const char *,
                       enum acl_entry_type, const char *, u32);
int pyr_add_default(struct pyr_lib_policy_db *, enum acl_entry_type,
                    const char *, u32);
u32 pyr_get_lib_perms(struct pyr_lib_policy_db *, const char *,
		      const char *);
u32 pyr_get_default_perms(struct pyr_lib_policy_db *, const char *);
int pyr_is_default_lib_policy(struct pyr_lib_policy_db *,
                              const char *);
int pyr_new_lib_policy_db(struct pyr_lib_policy_db **);
void pyr_free_lib_policy_db(struct pyr_lib_policy_db **);

struct pyr_profile;
int pyr_deserialize_lib_policy(struct pyr_profile *profile,
                               char *lp_str);

#endif /* __PYR_LIBPOLICY_H */
