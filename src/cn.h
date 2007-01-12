/* $Id: cn.h 1.18 05/12/07 10:05:43+02:00 vnuorval@tcs.hut.fi $ */

#ifndef __CN_H__
#define __CN_H__ 1

/* How long before binding expiry do we send a BRR */
#define CN_BRR_BEFORE_EXPIRY 2
extern const struct timespec cn_brr_before_expiry_ts;
#define CN_BRR_BEFORE_EXPIRY_TS cn_brr_before_expiry_ts

struct ip6_mh;
struct in6_addr_bundle;

extern void cn_recv_bu(const struct ip6_mh *mh,
		       const ssize_t len,
		       const struct in6_addr_bundle *in,
		       const int iif);

extern void cn_init(void);
extern void cn_cleanup(void);

#endif
