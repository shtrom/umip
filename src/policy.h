/* $Id: policy.h 1.49 05/12/07 10:05:44+02:00 vnuorval@tcs.hut.fi $ */

#ifndef __POLICY_H__
#define __POLICY_H__ 1

#include <netinet/in.h>
#include "list.h"

#define POL_MN_IF_DEF_PREFERENCE 0

struct home_addr_info;
struct md_inet6_iface;
struct list_head;
struct md_coa;
struct in6_addr_bundle;
struct ip6_mh_binding_update;
struct mh_options;
struct nd_router_advert;

struct policy_bind_acl_entry {
	struct list_head list;
	struct in6_addr hoa;
	int plen;
	int bind_policy;
};

int default_best_iface(const struct home_addr_info *hai, 
		       const struct md_inet6_iface *pref_iface, 
		       struct list_head *iface_list,
		       struct md_inet6_iface **best_iface);

int default_best_coa(const struct home_addr_info *hai,
		     const struct md_coa *pref_coa,
		     struct list_head *coa_list,
		     struct md_coa **best_coa);

int default_max_binding_life(const struct in6_addr_bundle *out_addrs,
			     const struct ip6_mh_binding_update *bu, 
			     const struct mh_options *opts,
			     const struct timespec *suggested,
			     struct timespec *lifetime);

int default_discard_binding(const struct in6_addr_bundle *out_addrs,
			    const struct ip6_mh_binding_update *bu, 
			    const struct mh_options *opts);

int default_use_bradv(const struct in6_addr *hoa, const struct in6_addr *coa,
		      const struct timespec *lft, struct timespec *refresh);

int default_use_keymgm(const struct in6_addr_bundle *out_addrs);

int default_accept_inet6_iface(const int iif, int *preference);

int default_accept_ra(const int iif,
		      const struct in6_addr *saddr,
		      const struct in6_addr *daddr,
		      const struct nd_router_advert *ra);

int default_get_ro_coa(const struct in6_addr *hoa, 
		       const struct in6_addr *cn,
		       struct in6_addr *coa);

void policy_cleanup(void);

int policy_init(void);

#endif
