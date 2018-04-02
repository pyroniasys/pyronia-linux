/** Provides utility functions and definitions for performing end-to-end
 * tests of the Pyronia LSM.
 *
 *@author Marcela S. Melara
 */

#ifndef __KERNEL_TEST_H
#define __KERNEL_TEST_H

#include "lib_policy.h"
#include "callgraph.h"
#include "audit.h"
#include "file.h"
#include "match.h"
#include "policy.h"
#include "pyronia.h"

static const char *test_libs[3];

static const char *test_names[2];

#define NUM_DEFAULT 8

static const char *default_names[NUM_DEFAULT];

static inline void init_testlibs(void) {
    test_libs[0] = "cam";
    test_libs[1] = "http";
    test_libs[2] = "img_processing";
}

static inline void init_testnames(void) {
    test_names[0] = "/tmp/cam0";
    test_names[1] = "127.0.0.1";
}

// these files should be allowed for all libs by default
static inline void init_default(void) {
  default_names[0] = "/etc/ld.so.cache";
  default_names[1] = "/lib/x86_64-linux-gnu/libc-2.23.so";
  default_names[2] = "/lib/x86_64-linux-gnu/libpyronia.so";
  default_names[3] = "/lib/x86_64-linux-gnu/libsmv.so";
  default_names[4] = "/lib/x86_64-linux-gnu/libpthread-2.23.so";
  default_names[5] = "/lib/x86_64-linux-gnu/libnl-genl-3.so.200.22.0";
  default_names[6] = "/lib/x86_64-linux-gnu/libnl-3.so.200.22.0";
  default_names[7] = "/lib/x86_64-linux-gnu/libm-2.23.so";
}

static inline int create_default_policy_entries(struct pyr_lib_policy_db *db,
                                                const char *lib) {

    struct pyr_lib_policy *policy = NULL;
    int err = 0;
    int i;
    
    policy = pyr_find_lib_policy(db, lib);
    
    if (policy == NULL) {
      return -1;
    }
    
    for (i = 0; i < NUM_DEFAULT; i++) {
        err = pyr_add_acl_entry(&(policy->acl), resource_entry,
                                default_names[i], 1, CAM_DATA);
        if (err) {
            return err;
        }
    }

    return 0;
}

// Create a dummy Pyronia policy for a test process
// This policy will be tested when the appropriate LSM
// checks are triggered at runtime
static inline int init_lib_policy(struct pyr_lib_policy_db **policy) {
    int err = 0;
    struct pyr_lib_policy_db *db;
    struct pyr_acl_entry *acl, *acl1;

    init_testlibs();
    init_testnames();
    init_default();

    // allocate the new policy db
    db = NULL;
    err = pyr_new_lib_policy_db(&db);
    if (err)
        goto fail;

    // create the ACL entry for "/tmp/cam0"
    acl = NULL;
    err = pyr_add_acl_entry(&acl, resource_entry, test_names[0], 1,
                            CAM_DATA);
    if (err) {
        goto fail;
    }

    // add a policy entry for "cam" to the permissions db
    err = pyr_add_lib_policy(&db, test_libs[0], acl);
    if (err) {
        goto fail;
    }

    // add the default policies for "cam"
    err = create_default_policy_entries(db, test_libs[0]);
    if (err) {
        goto fail;
    }

    // create the ACL entry for "127.0.0.1"
    acl1 = NULL;
    err = pyr_add_acl_entry(&acl1, net_entry, test_names[1], OP_CONNECT,
                            CAM_DATA);
    if (err) {
        goto fail;
    }

    // add a policy entry for "http" to the permissions db
    err = pyr_add_lib_policy(&db, test_libs[1], acl1);
    if (err) {
        goto fail;
    }

    // add the default policies for "http"
    err = create_default_policy_entries(db, test_libs[1]);
    if (err) {
        goto fail;
    }

    *policy = db;
    return 0;
 fail:
    pyr_free_lib_policy_db(&db);
    return err;
}

// Create a dummy callgraph with the given library for a test process
// This callgraph will be used to check the requested access/operation
// at runtime
static inline int init_callgraph(const char *lib, pyr_cg_node_t **cg) {
    int err = 0;

    pyr_cg_node_t *c = NULL;
    err = pyr_new_cg_node(&c, lib, CAM_DATA, NULL);
    if (err) {
        pyr_free_callgraph(&c);
        goto out;
    }

    *cg = c;
 out :
    return err;
}

// Set the file rule permissions given a policy DFA
static inline int set_file_perms(struct pyr_profile *profile) {

    unsigned int state;
    u32 perms;
    struct pyr_acl_entry *acl;
    struct pyr_lib_policy *policy;

    // set the permissions for the default files
    int i, j;
    for (i = 0; i < 2; i++){
        for (j = 0; j < NUM_DEFAULT; j++) {
            state = pyr_dfa_match(profile->file.dfa, profile->file.start, default_names[j]);

            perms = map_old_perms(dfa_user_allow(profile->file.dfa, state));
            perms |= PYR_MAY_META_READ;

            PYR_ERROR("Access to %s from %s: %d\n", default_names[j], test_libs[i], perms);

            policy = pyr_find_lib_policy(profile->lib_perm_db, test_libs[i]);

            if (policy == NULL) {
                PYR_ERROR("Couldn't find policy for %s\n", test_libs[i]);
                goto fail;
            }

            acl = pyr_find_lib_acl_entry(policy, default_names[j]);
            if (acl == NULL) {
                PYR_ERROR("Couldn't find ACL for %s in %s policy\n", default_names[j], test_libs[i]);
                goto fail;
            }

            acl->target.fs_resource.perms = perms;
        }
    }

    // set the permissions for the /tmp/cam0 resource
    state = pyr_dfa_match(profile->file.dfa, profile->file.start,
                          test_names[0]);

    perms = map_old_perms(dfa_user_allow(profile->file.dfa, state));
    perms |= PYR_MAY_META_READ;

    PYR_ERROR("Access to %s from %s: %d\n", test_names[0], test_libs[0], perms);

    policy = pyr_find_lib_policy(profile->lib_perm_db, test_libs[0]);

    if (policy == NULL) {
        PYR_ERROR("Couldn't find policy for %s\n", test_libs[0]);
        goto fail;
    }

    acl = pyr_find_lib_acl_entry(policy, test_names[0]);
    if (acl == NULL) {
        PYR_ERROR("Couldn't find ACL for %s in %s policy\n", test_names[0], test_libs[0]);
        goto fail;
    }

    acl->target.fs_resource.perms = perms;

    return 0;

 fail:
    return -1;
}

#endif
