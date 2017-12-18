/** Tests the Pyronia callgraph creation.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <string.h>

#include "testutil.h"

int main(int argc, char *argv[]) {

    const char *libs[4];
    libs[0] = "l1";
    libs[1] = "l2";
    libs[2] = "l3";
    libs[3] = "l4";

    pyr_cg_node_t *callgraph;
    int err;

    err = test_callgraph_creation(libs, 4, &callgraph);
    if (err) {
        PYR_ERROR("pyr_new_cg_node returned %d\n", err);
        return err;
    }

    pyr_cg_node_t *runner = callgraph;
    int i = 0;
    while(runner != NULL || i < 4) {
        if (strncmp(runner->lib, libs[i], strlen(libs[i]))) {
            PYR_ERROR("Expected %s, got %s\n", libs[i], runner->lib);
            return -1;
        }
        i++;
        runner = runner->child;
    }

    // make sure to free the memory
    pyr_free_callgraph(&callgraph);

    return 0;
}
