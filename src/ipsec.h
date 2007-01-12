/* $Id: ipsec.h 1.25 06/01/10 00:07:47+09:00 nakam@linux-ipv6.org $ */

#ifndef __IPSEC_H__
#define __IPSEC_H__
#include <linux/xfrm.h>
#include "list.h"

typedef enum {
	IPSEC_POLICY_TYPE_HOMEREGBINDING,
	IPSEC_POLICY_TYPE_BERROR,
	IPSEC_POLICY_TYPE_MH,
	IPSEC_POLICY_TYPE_MOBPFXDISC,
	IPSEC_POLICY_TYPE_ICMP,
	IPSEC_POLICY_TYPE_ANY,
	IPSEC_POLICY_TYPE_TUNNELHOMETESTING,
	IPSEC_POLICY_TYPE_TUNNELMH,
	IPSEC_POLICY_TYPE_TUNNELPAYLOAD
} ipsec_policy_type_t;

struct ipsec_policy_entry {
	struct list_head list;
	struct in6_addr ha_addr;
	struct in6_addr mn_addr;
	ipsec_policy_type_t type;
	int use_esp;
	int use_ah;
	int use_ipcomp;
	int action;
	unsigned int reqid_toha;
	unsigned int reqid_tomn;
};

int ipsec_policy_apply(const struct in6_addr *haaddr,
		       const struct in6_addr *hoa,
		       int (* func)(const struct in6_addr *haaddr,
				    const struct in6_addr *hoa,
				    struct ipsec_policy_entry *e, void *arg),
		       void *arg);
int ipsec_policy_walk(int (* func)(const struct in6_addr *haaddr,
				   const struct in6_addr *hoa,
				   struct ipsec_policy_entry *e, void *arg),
		      void *arg);
int ipsec_policy_entry_check(const struct in6_addr *haaddr,
			     const struct in6_addr *hoa,
			     int type);

int ha_ipsec_tnl_update(const struct in6_addr *haaddr,
			const struct in6_addr *hoa,
			const struct in6_addr *coa,
			const struct in6_addr *old_coa,
			int tunnel);

int ha_ipsec_tnl_pol_add(const struct in6_addr *our_addr, 
			 const struct in6_addr *peer_addr,
			 int tunnel);

int ha_ipsec_tnl_pol_del(const struct in6_addr *our_addr, 
			 const struct in6_addr *peer_addr,
			 int tunnel);

int mn_ipsec_tnl_update(const struct in6_addr *haaddr,
			const struct in6_addr *hoa,
			void *arg);

int mn_ipsec_tnl_pol_add(const struct in6_addr *haaddr,
			 const struct in6_addr *hoa,
			 void *arg);

int mn_ipsec_tnl_pol_del(const struct in6_addr *haaddr,
			 const struct in6_addr *hoa,
			 void *arg);

extern int ipsec_policy_dump_config(const struct in6_addr *haaddr,
				    const struct in6_addr *hoa,
				    struct ipsec_policy_entry *e, void *arg);

#endif	/* __IPSEC_H__ */
