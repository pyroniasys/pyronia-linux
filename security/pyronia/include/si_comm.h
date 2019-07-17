#ifndef __PYR_SI_COMM_H
#define __PYR_SI_COMM_H

#include "stack_inspector.h"

char *pyr_stack_request(u32 pid);
struct pyr_callstack_request *pyr_get_current_callstack_request(void);

#endif
