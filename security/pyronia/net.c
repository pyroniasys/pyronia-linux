/*
 * AppArmor security module
 *
 * This file contains AppArmor network mediation
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/inet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>

#include "include/pyronia.h"
#include "include/audit.h"
#include "include/context.h"
#include "include/net.h"
#include "include/policy.h"
#include "include/callgraph.h"

#ifdef PYR_TESTING
#if PYR_TESTING
#include "include/kernel_test.h"
#else
#include "include/userland_test.h"
#endif
#endif

#include "net_names.h"

struct pyr_fs_entry pyr_fs_entry_network[] = {
	PYR_FS_FILE_STRING("af_mask", PYR_FS_AF_MASK),
	{ }
};

/* audit callback for net specific fields */
static void audit_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	audit_log_format(ab, " family=");
	if (address_family_names[sa->u.net->family]) {
		audit_log_string(ab, address_family_names[sa->u.net->family]);
	} else {
		audit_log_format(ab, "\"unknown(%d)\"", sa->u.net->family);
	}
	audit_log_format(ab, " sock_type=");
	if (sock_type_names[sa->pyrd->net.type]) {
		audit_log_string(ab, sock_type_names[sa->pyrd->net.type]);
	} else {
		audit_log_format(ab, "\"unknown(%d)\"", sa->pyrd->net.type);
	}
	audit_log_format(ab, " protocol=%d", sa->pyrd->net.protocol);
}

/**
 * audit_net - audit network access
 * @profile: profile being enforced  (NOT NULL)
 * @op: operation being checked
 * @family: network family
 * @type:   network type
 * @protocol: network protocol
 * @sk: socket auditing is being applied to
 * @error: error code for failure else 0
 *
 * Returns: %0 or sa->error else other errorcode on failure
 */
static int audit_net(struct pyr_profile *profile, int op, u16 family, int type,
		     int protocol, struct sock *sk, int error)
{
	int audit_type = AUDIT_PYRONIA_AUTO;
	struct common_audit_data sa;
	struct pyronia_audit_data pyrd = { };
	struct lsm_network_audit net = { };
	if (sk) {
		sa.type = LSM_AUDIT_DATA_NET;
	} else {
		sa.type = LSM_AUDIT_DATA_NONE;
	}
	/* todo fill in socket addr info */
	sa.pyrd = &pyrd;
	sa.u.net = &net;
	sa.pyrd->op = op,
	sa.u.net->family = family;
	sa.u.net->sk = sk;
	sa.pyrd->net.type = type;
	sa.pyrd->net.protocol = protocol;
	sa.pyrd->error = error;

	if (likely(!sa.pyrd->error)) {
		u16 audit_mask = profile->net.audit[sa.u.net->family];
		if (likely((AUDIT_MODE(profile) != AUDIT_ALL) &&
			   !(1 << sa.pyrd->net.type & audit_mask)))
			return 0;
		audit_type = AUDIT_PYRONIA_AUDIT;
	} else {
		u16 quiet_mask = profile->net.quiet[sa.u.net->family];
		u16 kill_mask = 0;
		u16 denied = (1 << sa.pyrd->net.type);

		if (denied & kill_mask)
			audit_type = AUDIT_PYRONIA_KILL;

		if ((denied & quiet_mask) &&
		    AUDIT_MODE(profile) != AUDIT_NOQUIET &&
		    AUDIT_MODE(profile) != AUDIT_ALL)
			return COMPLAIN_MODE(profile) ? 0 : sa.pyrd->error;
	}

	return pyr_audit(audit_type, profile, GFP_KERNEL, &sa, audit_cb);
}

/**
 * pyr_net_perm - very coarse network access check
 * @op: operation being checked
 * @profile: profile being enforced  (NOT NULL)
 * @family: network family
 * @type:   network type
 * @protocol: network protocol
 *
 * Returns: %0 else error if permission denied
 */
int pyr_net_perm(int op, struct pyr_profile *profile, u16 family, int type,
		int protocol, struct sock *sk)
{
	u16 family_mask;
	int error;

	if ((family < 0) || (family >= AF_MAX))
		return -EINVAL;

	if ((type < 0) || (type >= SOCK_MAX))
		return -EINVAL;

	/* unix domain and netlink sockets are handled by ipc */
	if (family == AF_UNIX || family == AF_NETLINK)
		return 0;

	family_mask = profile->net.allow[family];

	error = (family_mask & (1 << type)) ? 0 : -EACCES;

	return audit_net(profile, op, family, type, protocol, sk, error);

}

/**
 * pyr_revalidate_sk - Revalidate access to a sock
 * @op: operation being checked
 * @sk: sock being revalidated  (NOT NULL)
 *
 * Returns: %0 else error if permission denied
 */
int pyr_revalidate_sk(int op, struct sock *sk)
{
	struct pyr_profile *profile;
	int error = 0;

	/* pyr_revalidate_sk should not be called from interrupt context
	 * don't mediate these calls as they are not task related
	 */
	if (in_interrupt())
		return 0;

	profile = __pyr_current_profile();
	if (!unconfined(profile))
		error = pyr_net_perm(op, profile, sk->sk_family, sk->sk_type,
				    sk->sk_protocol, sk);

	return error;
}

static void in_addr_to_str(struct sockaddr *sa, const char**addr_str)
{
    int in_addr, printed_bytes;
    char ip_str[16];

    if (sa->sa_family == AF_INET) {
        in_addr = (int)((struct sockaddr_in*)sa)->sin_addr.s_addr;

        printed_bytes = snprintf(ip_str, INET_ADDRSTRLEN, "%d.%d.%d.%d",
                                 (in_addr & 0xFF),
                                 ((in_addr & 0xFF00) >> 8),
                                 ((in_addr & 0xFF0000) >> 16),
                                 ((in_addr & 0xFF000000) >> 24));

        if (printed_bytes > sizeof(ip_str)) {
            *addr_str = NULL;
            return;
        }

        *addr_str = ip_str;
    }
    else {
        // FIXME: Actually support IPv6 addresses
        //in_addr = (int)((struct sockaddr_in6*)sa)->sin6_addr.s6_addr32[0];
        *addr_str = "IPv6 address";
    }
}

static void pyr_cg_net_perms(struct pyr_lib_policy_db *lib_perm_db,
                             const char *addr, u32 *lib_op) {

    pyr_cg_node_t *callgraph = NULL;
    u32 op = 0;

    #ifdef PYR_TESTING
    #if PYR_TESTING
    if (init_callgraph("http", &callgraph)) {
        PYR_ERROR("Net - Failed to create callgraph for %s\n", "http");
        goto out;
    }
    #endif
    #else
    // TODO: implement upcall to language runtime for callstack
    #endif

    if (pyr_compute_lib_perms(lib_perm_db,
                              callgraph,
                              addr, &op)) {
        PYR_ERROR("Net - Error verifying callgraph for %s\n", "http");
        goto out;
    }

 out:
    pyr_free_callgraph(&callgraph);
    *lib_op = op;
}

/**
 * pyr_revalidate_sk - Revalidate access to a sock
 * @op: operation being checked
 * @sk: sock being revalidated  (NOT NULL)
 *
 * Returns: %0 else error if permission denied
 */
int pyr_revalidate_sk_addr(int op, struct sock *sk, struct sockaddr *address)
{
	struct pyr_profile *profile;
	int error = 0;
        unsigned short sock_family;
        u32 lib_op;
        const char *addr;

	/* pyr_revalidate_sk should not be called from interrupt context
	 * don't mediate these calls as they are not task related
	 */
	if (in_interrupt())
		return 0;

	profile = __pyr_current_profile();
	if (!unconfined(profile)) {
            error = pyr_net_perm(op, profile, sk->sk_family, sk->sk_type,
                                 sk->sk_protocol, sk);

            // Pyronia hook: check the call stack to determine
            // if the requesting library has permissions to
            // complete this operation
            if (!error && !memcmp(profile->base.name, test_prof, strlen(test_prof))) {
                sock_family = sk->sk_family;

                /* unix domain and netlink sockets are handled by ipc */
                if (sock_family == AF_UNIX || sock_family == AF_NETLINK)
                    return 0;

                // make sure we have an address to check
                if (address == NULL) {
                    PYR_ERROR("Net - No address to check\n");
                    addr = "";
                }
                else {
                    in_addr_to_str(address, &addr);
                    if (addr == NULL) {
                        PYR_ERROR("Net - Failed to convert IP address to string\n");
                        addr = "";
                    }
                }

                // compute the permissions
                pyr_cg_net_perms(profile->lib_perm_db, addr,
                                 &lib_op);

                // this checks if the requested operation is an
                // exact match to the effective library operation
                if (op & ~lib_op) {
                    PYR_ERROR("Net - Expected %d, got %d; addr: %s\n",  \
                              lib_op, op, addr);
                    error = -EACCES;
                }
                else {
                    PYR_ERROR("Net - Operation allowed for %s\n", addr);
                }
            }
        }

	return error;
}
