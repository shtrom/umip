/*
 * $Id: policy.c 1.83 05/12/10 03:16:14+02:00 vnuorval@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 * 
 * Authors: Henrik Petander <petander@tcs.hut.fi>,
 *          Ville Nuorvala <vnuorval@tcs.hut.fi>,
 *
 * Copyright 2003-2004 GO-Core Project
 *
 * MIPL Mobile IPv6 for Linux is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2 of
 * the License.
 *
 * MIPL Mobile IPv6 for Linux is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MIPL Mobile IPv6 for Linux; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#else
#error "POSIX Thread Library required!"
#endif
#include <syslog.h>
#include <errno.h>
#ifdef HAVE_NETINET_IP6MH_H
#include <netinet/ip6mh.h>
#else
#include <netinet-ip6mh.h>
#endif

#include "debug.h"
#include "mh.h"
#include "mn.h"
#include "movement.h"
#include "util.h"
#include "conf.h"
#include "policy.h"
#include "hash.h"

#define POL_DEBUG_LEVEL 0

#define POLICY_ACL_HASHSIZE 32

pthread_rwlock_t policy_lock;
struct hash policy_bind_acl_hash;
int def_bind_policy = IP6_MH_BAS_PROHIBIT;

int default_best_iface(const struct home_addr_info *hai, 
		       const struct md_inet6_iface *pref_iface, 
		       struct list_head *iface_list,
		       struct md_inet6_iface **best_iface)
{
	struct list_head *list;
	int err = -ENODEV;

	*best_iface = NULL;

	list_for_each(list, iface_list) {
		struct md_inet6_iface *iface;
		iface = list_entry(list, struct md_inet6_iface, list);
		if (!list_empty(&iface->coas) && 
		    !list_empty(&iface->default_rtr) &&
		    ((*best_iface) == NULL || 
		     (*best_iface)->preference > iface->preference ||
		     ((*best_iface)->preference == iface->preference &&
		     iface == pref_iface))) {
			*best_iface = iface;
			err = 0;
		}
	}
	return err;
}
		      
int default_best_coa(const struct home_addr_info *hai,
		     const struct md_coa *pref_coa,
		     struct list_head *coa_list,
		     struct md_coa **best_coa)
{
	struct list_head *list;
	if (pref_coa == NULL) {
		list_for_each(list, coa_list) {
			struct md_coa *coa;
			coa = list_entry(list, struct md_coa, list);
			if (tsisset(coa->valid_time)) {
				*best_coa = coa;
				return 0;
			}
		}
	} else {
		list_for_each(list, pref_coa->list.prev) {
			struct md_coa *coa;
			if (list == coa_list)
				continue;
			coa = list_entry(list, struct md_coa, list);
			if (tsisset(coa->valid_time)) {
				*best_coa = coa;
				return 0;
			}
		}
	}
	*best_coa = NULL;
	return -EADDRNOTAVAIL;
}

/**
 * default_max_binding_life - binding lifetime policy
 * @hoa: MN's home address
 * @coa: MN's care-of address
 * @suggested: suggested lifetime
 * @lifetime: granted lifetime
 *
 * Stores configurable maximum lifetime for a binding in @lifetime.
 **/
int default_max_binding_life(const struct in6_addr_bundle *out_addrs,
			     const struct ip6_mh_binding_update *bu, 
			     const struct mh_options *opts,
			     const struct timespec *suggested,
			     struct timespec *lifetime)
{
	if (bu->ip6mhbu_flags & IP6_MH_BU_HOME)
		tssetsec(*lifetime, conf.MaxBindingLife);
	else
		*lifetime = *suggested;
	return 0;
}

/**
 * default_discard_binding - check for discard policy
 * @out_addrs: address bundle
 * @bu: binding update
 *
 * Checks if there is a policy to discard this BU.  Valid return
 * values are %IP6_MH_BAS_ACCEPTED, %IP6_MH_BAS_UNSPECIFIED, and
 * %IP6_MH_BAS_PROHIBIT.
 **/
int default_discard_binding(const struct in6_addr_bundle *out_addrs,
			    const struct ip6_mh_binding_update *bu, 
			    const struct mh_options *opts)
{
	int ret = def_bind_policy;
	struct policy_bind_acl_entry *acl;

	pthread_rwlock_rdlock(&policy_lock);
	acl = hash_get(&policy_bind_acl_hash, NULL, out_addrs->dst);
	if (acl != NULL) {
		ret = acl->bind_policy;
	}
	pthread_rwlock_unlock(&policy_lock);
	return ret;
}

/**
 * policy_use_bravd - use Binding refresh advice
 *
 * Checks if a Binding Refresh Advice should be inserted in a Binding
 * Ack.  Returns 0 if BRA should not be used, or refresh value in
 * seconds.
 **/
int default_use_bradv(const struct in6_addr *hoa, const struct in6_addr *coa,
		      const struct timespec *lft, struct timespec *refresh)
{
	return 0;
}

/**
 * default_use_keymgm - use K-bit
 * @addrs: address bundle
 *
 * Determine whether to use the Key Management Mobility Capability bit
 * for addresses given in @addrs.
 **/
int default_use_keymgm(const struct in6_addr_bundle *out_addrs)
{
	return 0;
}

/**
 * policy_accept_inet6_iface - use interface for MIPv6
 * @ifindex: interface index
 *
 * Determine whether to allow movement events from interface @ifindex or not
 **/
int default_accept_inet6_iface(const int iif, int *preference)
{
	struct list_head *list;

	*preference = POL_MN_IF_DEF_PREFERENCE;
	
	list_for_each(list, &conf.net_ifaces) {
		struct net_iface *nif;
		nif = list_entry(list, struct net_iface, list);
		if (nif->ifindex == iif) {
			if (is_mn()) {
				*preference = nif->mn_if_preference;
				return 1;
			} else
				return 0;
		}
	}
	return conf.MnUseAllInterfaces;
}

int default_accept_ra(const int iif,
		      const struct in6_addr *saddr,
		      const struct in6_addr *daddr,
		      const struct nd_router_advert *ra)
{
	return 1;
}

/**
 * default_get_ro_coa - get a suitable care-of address for RO
 * @hoa: own home address
 * @cn: CN address
 * @coa: care-of address
 **/
int default_get_ro_coa(const struct in6_addr *hoa,
		       const struct in6_addr *cn, struct in6_addr *coa)
{
	int ret;
	if ((ret = mn_get_home_reg_coa(hoa, coa)) < 0){
		BUG("no home address info");
	}
	return ret;
}

static int policy_bind_acle_cleanup(void *data, void *arg)
{
	struct policy_bind_acl_entry *acl = data;
	free(acl);
	return 0;
}

static void policy_bind_acl_cleanup(void)
{
	def_bind_policy = IP6_MH_BAS_PROHIBIT;
	hash_iterate(&policy_bind_acl_hash, policy_bind_acle_cleanup, NULL);
	hash_cleanup(&policy_bind_acl_hash);
}

void policy_cleanup(void)
{
	pthread_rwlock_wrlock(&policy_lock);
	policy_bind_acl_cleanup();
	pthread_rwlock_unlock(&policy_lock);
}

int policy_bind_acl_add(struct policy_bind_acl_entry *acl)
{
	int err;
	err = hash_add(&policy_bind_acl_hash, acl, NULL, &acl->hoa);
	if (!err) {
		list_del(&acl->list);
	}
	return err;
}

int policy_bind_acl_config(void)
{
	struct list_head *list, *n;
	int err;

	pthread_rwlock_wrlock(&policy_lock);

	err = hash_init(&policy_bind_acl_hash, SINGLE_ADDR, 
			POLICY_ACL_HASHSIZE);
	def_bind_policy = conf.DefaultBindingAclPolicy;

	list_for_each_safe(list, n, &conf.bind_acl) {
		struct policy_bind_acl_entry *acl;
		acl = list_entry(list, struct policy_bind_acl_entry, list);
		if ((err = policy_bind_acl_add(acl)) < 0) {
			policy_bind_acl_cleanup();
			break;
		}
	}
	pthread_rwlock_unlock(&policy_lock);
	return err;
}

int policy_init(void)
{
	if (pthread_rwlock_init(&policy_lock, NULL))
		return -1;
	return policy_bind_acl_config();
}

