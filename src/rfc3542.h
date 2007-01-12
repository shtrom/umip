/* $Id: rfc3542.h 1.2 05/11/17 22:35:25+02:00 vnuorval@tcs.hut.fi $ */

#ifndef __RFC3542_H__
#define __RFC3542_H__ 1

#include <config.h>
#include <netinet/in.h>

/* This section is to provide limited Advanced Socket API for IPv6
 * support in non-RFC3542-compliant environments.  Any missing
 * functions will be compiled in libmissing/libmissing.a. */
#if !HAVE_INET6_OPT_FIND
extern
int inet6_opt_find(void *, socklen_t, int, uint8_t, socklen_t *, void **);
#endif
#if !HAVE_INET6_RTH_SPACE
extern socklen_t inet6_rth_space(int, int);
#endif
#if !HAVE_INET6_RTH_INIT
extern void *inet6_rth_init(void *, socklen_t, int, int);
#endif
#if !HAVE_INET6_RTH_ADD
extern int inet6_rth_add(void *, const struct in6_addr *);
#endif
#if !HAVE_INET6_RTH_GETADDR
extern struct in6_addr *inet6_rth_getaddr(const void *, int);
#endif
#if !HAVE_INET6_RTH_GETTYPE
extern int inet6_rth_gettype(const void *);
#endif

#ifndef IPV6_RTHDR_TYPE_2
#define IPV6_RTHDR_TYPE_2 2
#endif

/* Software only works on >=2.6.14 kernels, so RFC3542 values for
 * socket options must be used.  This is not supposed to be complete.
 * Only options that are actually used are here. */


#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO        49
#ifdef IPV6_PKTINFO
#undef IPV6_PKTINFO
#define IPV6_PKTINFO            50
#endif
#endif

#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT       51
#ifdef IPV6_HOPLIMIT
#undef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT		52
#endif
#endif

#ifndef IPV6_RECVRTHDR
#define IPV6_RECVRTHDR          56
#ifdef IPV6_RTHDR
#undef IPV6_RTHDR
#define IPV6_RTHDR		57
#endif
#endif

#ifndef IPV6_RECVDSTOPTS
#define IPV6_RECVDSTOPTS        58
#ifdef IPV6_DSTOPTS
#undef IPV6_DSTOPTS
#define IPV6_DSTOPTS		59
#endif
#endif

#endif /* __RFC3542_H__ */
