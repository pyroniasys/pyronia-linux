/** Tests the Pyronia library permissions
 * verification.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <string.h>

#include "testutil.h"

// create a policy with all libraries
// and build a callgraph that results in allowed permissions
static int test_policy_verification_success(const char* libs[],
                                            const char* names[],
                                            const char* net[]) {
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, net, &db);
    if (err) {
        goto out;
    }

    pyr_cg_node_t *callgraph;
    // create a callgraph with only l3 -> l4
    // these are expected to have the same permissions
    err = test_callgraph_creation(libs+2, 2, &callgraph);
    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_compute_lib_perms(db, callgraph, names[2], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // we should get permissions of 1 because both libraries in the
    // callgraph have permission to access `names[2]`
    if (lib_perms != PERM1) {
        err = 1;
        PYR_ERROR("Expecting effective permissions of 1, got %d\n",
                  lib_perms);
        goto out;
    }

    pyr_free_callgraph(&callgraph);

    // now create a callgraph with only l4
    // and check the network operation
    err = test_callgraph_creation(libs+3, 1, &callgraph);
    if (err) {
        goto out;
    }

    uint32_t lib_op;
    err = pyr_compute_lib_perms(db, callgraph, net[3], &lib_op);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // we should get permission of 1 because the library in the
    // callgraph has permission to perform NETOP1 for `net[3]`
    if (lib_op != NETOP1) {
        err = 1;
        PYR_ERROR("Expecting effective net operations of 1, got %d\n",
                  lib_op);
        goto out;
    }
 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_policy_verification_fail(const char* libs[],
                                         const char* names[],
                                         const char* net[]) {
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, net, &db);
    if (err) {
        goto out;
    }

    pyr_cg_node_t *callgraph;
    err = test_callgraph_creation(libs, 4, &callgraph);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_compute_lib_perms(db, callgraph, names[0], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // we should get permissions of 0 because each library in the
    // callgraph has permission to a distinct `names[i]`
    if (lib_perms != 0) {
        err = 1;
        PYR_ERROR("Expecting effective permissions of 0, got %d\n",
                  lib_perms);
        goto out;
    }

    uint32_t lib_op;
    err = pyr_compute_lib_perms(db, callgraph, net[0], &lib_op);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // we should get lib_op of 0 because each library in the
    // callgraph has permission to a distinct `net[i]`
    if (lib_op != 0) {
        err = 1;
        PYR_ERROR("Expecting effective net operations of 0, got %d\n",
                  lib_perms);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_against_requested_perms_success(const char* libs[],
                                                const char* names[],
                                                const char *net[]) {
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, net, &db);
    if (err) {
        goto out;
    }

    pyr_cg_node_t *callgraph;
    // create a callgraph with only l3 -> l4
    // these are expected to have the same permissions
    err = test_callgraph_creation(libs+2, 2, &callgraph);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_compute_lib_perms(db, callgraph, names[2], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // for the reasoning behind these tests, please see tests.h:
    // a bitwise AND of the requested permission and the negated
    // effective permissions should result in 0, which implies an
    // exact match in requested and the permissions

    // if requested permission is PERM1, we should get an allowed
    // operation because ~1 & 1 = 0
    if (PERM1 & ~lib_perms) {
        err = 1;
        PYR_ERROR("Expecting allowed with requested access of %d, and permissions %d\n",
                  PERM1, lib_perms);
        goto out;
    }

    // if requested permission is PERM2, we should get a disallowed
    // operation because ~1 & 2 = 2
    if (!(PERM2 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM2);
        goto out;
    }

    // if requested permission is PERM3, we should get a disallowed
    // operation because ~1 & 3 = 2
    if (!(PERM3 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM3);
        goto out;
    }

    pyr_free_callgraph(&callgraph);

    // now create a callgraph with only l4
    // and check the network operation
    err = test_callgraph_creation(libs+3, 1, &callgraph);
    if (err) {
        goto out;
    }

    uint32_t lib_op;
    err = pyr_compute_lib_perms(db, callgraph, net[3], &lib_op);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // if requested permission is NETOP1, we should get an allowed
    // operation because ~1 & 1 = 0
    if (NETOP1 & ~lib_op) {
        err = 1;
        PYR_ERROR("Expecting allowed with requested op of %d, and permissions %d\n",
                  NETOP1, lib_op);
        goto out;
    }

    // if requested permission is NETOP2, we should get a disallowed
    // operation because ~1 & 2 = 2
    if (!(NETOP2 & ~lib_op)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP2);
        goto out;
    }

    // if requested permission is NETOP3, we should get a disallowed
    // operation because ~1 & 3 = 2
    if (!(NETOP3 & ~lib_op)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP3);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_against_requested_perms_failed(const char* libs[],
                                               const char* names[],
                                               const char* net[]) {
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, net, &db);
    if (err) {
        goto out;
    }

    pyr_cg_node_t *callgraph;
    err = test_callgraph_creation(libs, 4, &callgraph);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_compute_lib_perms(db, callgraph, names[0], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // for the reasoning behind these tests, please see tests.h:
    // a bitwise AND of the requested permission and the negated
    // effective permissions should result in 0, which implies an
    // exact match in requested and the permissions

    // if requested permission is PERM1, we should get a disallowed
    // operation because ~0 & 1 = 1
    if (!(PERM1 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM1);
        goto out;
    }

    // if requested permission is PERM2, we should get a disallowed
    // operation because ~0 & 2 = 2
    if (!(PERM2 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM2);
        goto out;
    }

    // if requested permission is PERM3, we should get a disallowed
    // operation because ~0 & 3 = 3
    if (!(PERM3 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM3);
        goto out;
    }

    uint32_t lib_op;
    err = pyr_compute_lib_perms(db, callgraph, net[0], &lib_op);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // if requested permission is NETOP1, we should get a disallowed
    // operation because ~0 & 1 = 1
    if (!(NETOP1 & ~lib_op)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP1);
        goto out;
    }

    // if requested permission is NETOP2, we should get a disallowed
    // operation because ~0 & 2 = 2
    if (!(NETOP2 & ~lib_op)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP2);
        goto out;
    }

    // if requested permission is NETOP3, we should get a disallowed
    // operation because ~0 & 3 = 3
    if (!(NETOP3 & ~lib_op)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP3);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_with_unrecorded_lib_success(const char* libs[],
                                            const char* names[],
                                            const char *net[]) {
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, net, &db);
    if (err) {
        goto out;
    }

    pyr_cg_node_t *callgraph;
    // create a callgraph with only l3 -> l4 -> l5
    // these are expected to have the same permissions
    err = test_callgraph_creation(libs+2, 3, &callgraph);

    if (err) {
        goto out;
    }

    // create a callgraph with l1 -> l5 -> l2
    // these are expected to have the same permissions
    const char* libs1[3];
    libs1[0] = libs[0];
    libs1[1] = libs[4];
    libs1[2] = libs[1];

    pyr_cg_node_t *callgraph1;
    err = test_callgraph_creation(libs1, 3, &callgraph1);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_compute_lib_perms(db, callgraph, names[2], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    uint32_t lib_perms1;
    err = pyr_compute_lib_perms(db, callgraph1, names[0], &lib_perms1);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // for the reasoning behind these tests, please see tests.h:
    // a bitwise AND of the requested permission and the negated
    // effective permissions should result in 0, which implies an
    // exact match in requested and the permissions

    // if requested permission is PERM1, we should get an allowed
    // operation because ~1 & 1 = 0
    if ((PERM1 & ~lib_perms) || (PERM1 & ~lib_perms1)) {
        err = 1;
        PYR_ERROR("Expecting allowed with requested access of %d, and permissions %d\n",
                  PERM1, lib_perms);
        goto out;
    }

    // if requested permission is PERM2, we should get a disallowed
    // operation because ~1 & 2 = 2
    if (!(PERM2 & ~lib_perms) || !(PERM2 & ~lib_perms1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM2);
        goto out;
    }

    // if requested permission is PERM3, we should get a disallowed
    // operation because ~1 & 3 = 2
    if (!(PERM3 & ~lib_perms) || !(PERM3 & ~lib_perms1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM3);
        goto out;
    }

    pyr_free_callgraph(&callgraph);
    pyr_free_callgraph(&callgraph1);

    // now create a callgraph with only l4 -> l5
    // and check the network operation
    err = test_callgraph_creation(libs+3, 2, &callgraph);
    if (err) {
        goto out;
    }

    uint32_t lib_op;
    err = pyr_compute_lib_perms(db, callgraph, net[3], &lib_op);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // if requested permission is NETOP1, we should get an allowed
    // operation because ~1 & 1 = 0
    if (NETOP1 & ~lib_op) {
        err = 1;
        PYR_ERROR("Expecting allowed with requested op of %d, and permissions %d\n",
                  NETOP1, lib_op);
        goto out;
    }

    // if requested permission is NETOP2, we should get a disallowed
    // operation because ~1 & 2 = 2
    if (!(NETOP2 & ~lib_op)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP2);
        goto out;
    }

    // if requested permission is NETOP3, we should get a disallowed
    // operation because ~1 & 3 = 2
    if (!(NETOP3 & ~lib_op)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP3);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_with_unrecorded_lib_failed(const char* libs[],
                                               const char* names[],
                                               const char* net[]) {
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, net, &db);
    if (err) {
        goto out;
    }

    pyr_cg_node_t *callgraph;
    err = test_callgraph_creation(libs, 5, &callgraph);

    if (err) {
        goto out;
    }

    // create a callgraph with l1 -> l5 -> l3
    // these are expected to have different permissions
    const char* libs1[3];
    libs1[0] = libs[0];
    libs1[1] = libs[4];
    libs1[2] = libs[2];

    pyr_cg_node_t *callgraph1;
    err = test_callgraph_creation(libs1, 3, &callgraph1);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_compute_lib_perms(db, callgraph, names[2], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    uint32_t lib_perms1;
    err = pyr_compute_lib_perms(db, callgraph1, names[0], &lib_perms1);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // for the reasoning behind these tests, please see tests.h:
    // a bitwise AND of the requested permission and the negated
    // effective permissions should result in 0, which implies an
    // exact match in requested and the permissions

    // if requested permission is PERM1, we should get a disallowed
    // operation because ~0 & 1 = 1
    if (!(PERM1 & ~lib_perms) || !(PERM1 & ~lib_perms1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM1);
        goto out;
    }

    // if requested permission is PERM2, we should get a disallowed
    // operation because ~0 & 2 = 2
    if (!(PERM2 & ~lib_perms) || !(PERM2 & ~lib_perms1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM2);
        goto out;
    }

    // if requested permission is PERM3, we should get a disallowed
    // operation because ~0 & 3 = 3
    if (!(PERM3 & ~lib_perms) || !(PERM3 & ~lib_perms1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM3);
        goto out;
    }

    uint32_t lib_op;
    err = pyr_compute_lib_perms(db, callgraph, net[0], &lib_op);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    uint32_t lib_op1;
    err = pyr_compute_lib_perms(db, callgraph1, net[0], &lib_op1);
    if (err) {
        PYR_ERROR("pyr_compute_lib_perms returns %d\n", err);
        goto out;
    }

    // if requested permission is NETOP1, we should get a disallowed
    // operation because ~0 & 1 = 1
    if (!(NETOP1 & ~lib_op) || !(NETOP1 & ~lib_op1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP1);
        goto out;
    }

    // if requested permission is NETOP2, we should get a disallowed
    // operation because ~0 & 2 = 2
    if (!(NETOP2 & ~lib_op) || !(NETOP2 & ~lib_op1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP2);
        goto out;
    }

    // if requested permission is NETOP3, we should get a disallowed
    // operation because ~0 & 3 = 3
    if (!(NETOP3 & ~lib_op) || !(NETOP3 & ~lib_op1)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested op of %d\n",
                  NETOP3);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    pyr_free_callgraph(&callgraph1);
    return err;
}

static int test_unrecorded_root_lib(const char* libs[],
                                         const char* names[],
                                         const char* net[]) {
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, net, &db);
    if (err) {
        goto out;
    }

    pyr_cg_node_t *callgraph;
    const char *libs1[3];
    libs1[0] = libs[4];
    libs1[1] = libs[0];
    libs1[2] = libs[1];
    err = test_callgraph_creation(libs1, 3, &callgraph);
    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_compute_lib_perms(db, callgraph, names[0], &lib_perms);
    if (err != -1) {
        PYR_ERROR("Expecting error from pyr_compute_lib_perms, got %d\n", err);
        goto out;
    }
    err = 0;

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

int main(int argc, char *argv[]) {

    const char *libs[5];
    libs[0] = "l1";
    libs[1] = "l2";
    libs[2] = "l3";
    libs[3] = "l4";
    libs[4] = "l5";

    const char *names[4];
    names[0] = "/dev/cam0";
    names[1] = "/dev/cam0";
    names[2] = "/dev/cam1";
    names[3] = "/dev/cam1";

    const char *net[4];
    net[0] = "0.0.0.0";
    net[1] = "8.8.8.8";
    net[2] = "127.0.0.1";
    net[3] = "255.255.255.255";

    int err = 0;
    int final_err = err;
    int num_tests = 0;
    int passed = 0;
    PYR_DEBUG("Test successful policy verification... \n");
    num_tests++;
    err = test_policy_verification_success(libs, names, net);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test failed policy verification... \n");
    num_tests++;
    err = test_policy_verification_fail(libs, names, net);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test allowed access against requested permissions... \n");
    num_tests++;
    err = test_against_requested_perms_success(libs, names, net);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test failed access against requested permissions... \n");
    num_tests++;
    err = test_against_requested_perms_failed(libs, names, net);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test allowed access with unrecorded library in callgraph... \n");
    num_tests++;
    err = test_with_unrecorded_lib_success(libs, names, net);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test failed access with unrecorded library in callgraph... \n");
    num_tests++;
    err = test_with_unrecorded_lib_failed(libs, names, net);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test unrecorded top-level library in callgraph... \n");
    num_tests++;
    err = test_unrecorded_root_lib(libs, names, net);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Passed %d/%d tests\n", passed, num_tests);
    return final_err;
}
