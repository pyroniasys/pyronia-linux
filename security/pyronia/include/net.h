/*
 * AppArmor security module
 *
 * This file contains AppArmor network mediation definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_NET_H
#define __PYR_NET_H

#include <net/sock.h>

#include "pyroniafs.h"

/* struct pyr_net - network confinement data
 * @allowed: basic network families permissions
 * @audit_network: which network permissions to force audit
 * @quiet_network: which network permissions to quiet rejects
 */
struct pyr_net {
	u16 allow[AF_MAX];
	u16 audit[AF_MAX];
	u16 quiet[AF_MAX];
};

extern struct pyr_fs_entry pyr_fs_entry_network[];

extern int pyr_net_perm(int op, struct pyr_profile *profile, u16 family,
		       int type, int protocol, struct sock *sk);
extern int pyr_revalidate_sk(int op, struct sock *sk);
extern int pyr_revalidate_sk_addr(int op, struct sock *sk, struct sockaddr *address);

static inline void pyr_free_net_rules(struct pyr_net *new)
{
	/* NOP */
}

#endif /* __PYR_NET_H */
