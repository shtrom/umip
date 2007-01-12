/* $Id: retrout.h 1.37 05/12/10 03:59:28+02:00 vnuorval@tcs.hut.fi $ */

#ifndef __RETROUT_H__
#define __RETROUT_H__ 1

struct bulentry;
struct ip6_mh;
struct mn_addr;
struct in6_addr_bundle;
struct tq_elem;

int mn_rr_post_home_handoff(void *bule, void *vcoa);

int mn_rr_start_handoff(void *vbule, void *vcoa);

void mn_rr_check_entry(struct tq_elem *tqe); 

void mn_start_ro(struct in6_addr *cn_addr, struct in6_addr *home_addr,
		 struct mn_addr *coa);

int mn_rr_cond_start_hot(void *bule, int uncond);

int mn_rr_cond_start_cot(struct bulentry *bule, struct bulentry **co_bule, 
			 struct in6_addr *coa, int if_index, int uncond);

void rr_init(void);
void rr_cleanup(void);

#endif
