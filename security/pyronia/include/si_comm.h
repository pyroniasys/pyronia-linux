#ifndef __PYR_SI_COMM_H
#define __PYR_SI_COMM_H

#include <uapi/linux/pyronia_mac.h>
#include "stack_inspector.h"

pyr_cg_node_t *pyr_stack_request(u32 pid);
struct pyr_callstack_request *pyr_get_current_callstack_request(void);

#endif
