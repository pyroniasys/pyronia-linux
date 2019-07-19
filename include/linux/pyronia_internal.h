/*
 * Pyronia security module
 *
 * Defines the syscall stack logging interface.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_INTERNAL_H
#define __PYR_INTERNAL_H

enum pyr_user_resource {
    FILENAME_RESOURCE,
    SOCKADDR_RESOURCE,
};

int copy_userspace_stack_hash(void __user **, enum pyr_user_resource);

#endif /* __PYR_INTERNAL_H */
