/** Defines functions needed for testing.
 * The functions here are really aliases for functions defined in pyronia.h,
 * which needs to replace this header file when running Pyronia in kernel
 * mode.
 *
 *@author Marcela S. Melara
 */

#ifndef __TEST_H
#define __TEST_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint32_t u32;

static inline void *kvzalloc(size_t size) {
    return malloc(size);
}

static inline void kvfree(void *p) {
    free(p);
}

#define PYR_DEBUG(fmt, args...)                                     \
  do {								       \
    printf("\t[pyr] ");						       \
    printf(fmt, ##args);					       \
  } while (0)

#define PYR_ERROR(fmt, args...)                                         \
  do {									\
    printf("\t[pyr] Error: ");                                          \
    printf(fmt, ##args);						\
  } while (0)

#endif
