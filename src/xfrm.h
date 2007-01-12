/* $Id: xfrm.h 1.70 05/12/13 13:17:21+02:00 vnuorval@tcs.hut.fi $ */
#ifndef __XFRM_H__
#define __XFRM_H__

#include <linux/xfrm.h>
#include "list.h"

#define MIP6_PRIO_HOME_ERROR		1
#define MIP6_PRIO_HOME_SIG		2
#define MIP6_PRIO_HOME_BLOCK		3
#define MIP6_PRIO_HOME_DATA_IPSEC	4
#define MIP6_PRIO_HOME_DATA		5
#define MIP6_PRIO_RO_SIG_IPSEC		6	/* XXX: BU between MN-MN with IPsec */
#define MIP6_PRIO_RO_SIG		7	/* XXX: BU between MN-CN */
#define MIP6_PRIO_RO_SIG_ANY		8
#define MIP6_PRIO_RO_SIG_RR		9	/* XXX: MH(or HoTI/HoT) between MN-CN */
#define MIP6_PRIO_RO_BLOCK		10
#define MIP6_PRIO_RO_NO_SIG_ANY		11
#define MIP6_PRIO_NO_RO_DATA		12
#define MIP6_PRIO_RO_BULE_BCE_DATA	13
#define MIP6_PRIO_RO_BULE_DATA		14
#define MIP6_PRIO_RO_BCE_DATA		15
#define MIP6_PRIO_RO_TRIG		16
#define MIP6_PRIO_RO_TRIG_ANY		17
#define MIP6_PRIO_RO_DATA_ANY		18

typedef enum {
	MIP6_TYPE_MOVEMENT_UNKNOWN = 0,
	MIP6_TYPE_MOVEMENT_HL2FL,	/* Home to Foreign */
	MIP6_TYPE_MOVEMENT_FL2FL,	/* Foreign to Foreign */
	MIP6_TYPE_MOVEMENT_FL2HL,	/* Foreign to Home */
} movement_t;

struct xfrm_ro_pol {
	struct list_head list;
	struct in6_addr cn_addr;
	int do_ro;     /* 1 for RO, 0 for reverse tunnel */
};

int xfrm_init(void);
void xfrm_cleanup(void);

struct in6_addr;
struct bulentry;
struct ipsec_policy_entry;
struct home_addr_info;

int xfrm_add_bce(const struct in6_addr *our_addr,
		 const struct in6_addr *peer_addr,
		 const struct in6_addr *coa,
		 int replace);

void xfrm_del_bce(const struct in6_addr *our_addr,
		  const struct in6_addr *peer_addr);

int xfrm_pre_bu_add_bule(struct bulentry *bule);
int xfrm_post_ba_mod_bule(struct bulentry *bule);
void xfrm_del_bule(struct bulentry *bule);

long xfrm_last_used(const struct in6_addr *daddr,
		    const struct in6_addr *saddr, 
		    const int proto,
		    const struct timespec *now);

int mn_ro_pol_add(struct home_addr_info *hai, int ifindex, int changed);
void mn_ro_pol_del(struct home_addr_info *hai, int ifindex, int changed);

int mn_ipsec_recv_bu_tnl_pol_add(struct bulentry *bule, int ifindex,
				 struct ipsec_policy_entry *e);
void mn_ipsec_recv_bu_tnl_pol_del(struct bulentry *bule, int ifindex,
				  struct ipsec_policy_entry *e);

int cn_wildrecv_bu_pol_add(void);
void cn_wildrecv_bu_pol_del(void);

int xfrm_block_policy(struct home_addr_info *hai);
void xfrm_unblock_policy(struct home_addr_info *hai);

int xfrm_block_hoa(struct home_addr_info *hai);
void xfrm_unblock_hoa(struct home_addr_info *hai);

int ha_mn_ipsec_pol_mod(struct in6_addr *haaddr,
			struct in6_addr *hoa, int add);

int xfrm_policy_mod(struct xfrm_userpolicy_info *sp,
		    struct xfrm_user_tmpl *tmpl,
		    int num_tmpl,
		    int cmd);

static inline int pre_bu_bul_update(struct bulentry *bule)
{
	return xfrm_pre_bu_add_bule(bule);
}

static inline int post_ba_bul_update(struct bulentry *bule)
{
	return xfrm_post_ba_mod_bule(bule);
} 

#endif /* __XFRM_H__ */
