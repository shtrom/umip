/*
 * $Id: rtnl.c 1.56 06/05/15 19:50:13+03:00 vnuorval@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 *
 * Authors:
 *  Ville Nuorvala <vnuorval@tcs.hut.fi>,
 *  Antti Tuominen <anttit@tcs.hut.fi>
 *
 * Copyright 2003-2005 Go-Core Project
 * Copyright 2003-2006 Helsinki University of Technology
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

#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <libnetlink.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "debug.h"
#include "rtnl.h"
#include "conf.h"
#include "movement.h"

#define RT_DEBUG_LEVEL 1

#if RT_DEBUG_LEVEL >= 1
#define RTDBG dbg
#else
#define RTDBG(...)
#endif /* RTDBG */

int rtnl_do(int proto, struct nlmsghdr *sn, struct nlmsghdr *rn)
{
	struct rtnl_handle rth;
	int err;
	if (rtnl_open_byproto(&rth, 0, proto) < 0) {
		dbg("huh?\n");
		return -1;
	}
	err = rtnl_talk(&rth, sn, 0, 0, rn, NULL, NULL);
	rtnl_close(&rth);
	return err;
}

int addr_do(const struct in6_addr *addr, int plen, int ifindex, void *arg,
	    int (*do_callback)(struct ifaddrmsg *ifa,
			       struct rtattr *rta_tb[], void *arg))
{
	uint8_t sbuf[256];
	uint8_t rbuf[256];
	struct nlmsghdr *sn, *rn;
	struct ifaddrmsg *ifa;
	int err;
	struct rtattr *rta_tb[IFA_MAX+1];

	memset(sbuf, 0, sizeof(sbuf));
	sn = (struct nlmsghdr *)sbuf;
	sn->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	sn->nlmsg_flags = NLM_F_REQUEST;
	sn->nlmsg_type = RTM_GETADDR;

	ifa = NLMSG_DATA(sn);
	ifa->ifa_family = AF_INET6;
	ifa->ifa_prefixlen = plen;
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_index = ifindex;

	addattr_l(sn, sizeof(sbuf), IFA_LOCAL, addr, sizeof(*addr));

	memset(rbuf, 0, sizeof(rbuf));
	rn = (struct nlmsghdr *)rbuf;
	err = rtnl_route_do(sn, rn);
#ifdef __DSMIP_DEBUG__
	printf("route_do returns %d\n", err);
#endif
	if (err < 0) {
		rn = sn;
		ifa = NLMSG_DATA(rn);
	} else {
		ifa = NLMSG_DATA(rn);

		if (rn->nlmsg_type != RTM_NEWADDR ||
		    rn->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)) ||
		    ifa->ifa_family != AF_INET6) {
#ifdef __DSMIP_DEBUG__
		  printf("EINVAL\n");
#endif
			return -EINVAL;
		}
	}
	memset(rta_tb, 0, sizeof(rta_tb));
	parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
		     rn->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

	if (!rta_tb[IFA_ADDRESS])
		rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

	if (!rta_tb[IFA_ADDRESS] ||
	    !IN6_ARE_ADDR_EQUAL(RTA_DATA(rta_tb[IFA_ADDRESS]), addr)) {
#ifdef __DSMIP_DEBUG__
	  printf("INVAL2\n");
#endif
		return -EINVAL;
	}
	if (do_callback)
		err = do_callback(ifa, rta_tb, arg);

	return err;

}

int addr4_do(const struct in_addr *addr4, int plen4, int ifindex, void *arg,
		int (*do_callback)(struct ifaddrmsg *ifa, void *arg))
{
		uint8_t sbuf[256];
		uint8_t rbuf[256];
		struct nlmsghdr *sn, *rn;
		struct ifaddrmsg *ifa;
		int err;

		memset(sbuf, 0, sizeof(sbuf));
		sn = (struct nlmsghdr *)sbuf;
		sn->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
		sn->nlmsg_flags = NLM_F_REQUEST;
		sn->nlmsg_type = RTM_GETADDR;

		ifa = NLMSG_DATA(sn);
		ifa->ifa_family = AF_INET;
		ifa->ifa_prefixlen = plen4;
		ifa->ifa_scope = RT_SCOPE_UNIVERSE;
		ifa->ifa_index = ifindex;

		addattr_l(sn, sizeof(sbuf), IFA_LOCAL, addr4, sizeof(*addr4));

		memset(rbuf, 0, sizeof(rbuf));
		rn = (struct nlmsghdr *)rbuf;
		err = rtnl_route_do(sn, rn);
		if (err < 0) {
			rn = sn;
			ifa = NLMSG_DATA(rn);
		} else {
			ifa = NLMSG_DATA(rn);
		}

		if (do_callback)
			err = do_callback(ifa, arg);

		return err;
}

static int addr_mod(int cmd, uint16_t nlmsg_flags,
		    const struct in6_addr *addr, uint8_t plen,
		    uint8_t flags, uint8_t scope, int ifindex,
		    uint32_t prefered, uint32_t valid)

{
	uint8_t buf[256];
	struct nlmsghdr *n;
	struct ifaddrmsg *ifa;

	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	n->nlmsg_flags = NLM_F_REQUEST | nlmsg_flags;
	n->nlmsg_type = cmd;

	ifa = NLMSG_DATA(n);
	ifa->ifa_family = AF_INET6;
	ifa->ifa_prefixlen = plen;
	ifa->ifa_flags = flags;
	ifa->ifa_scope = scope;
	ifa->ifa_index = ifindex;

	addattr_l(n, sizeof(buf), IFA_LOCAL, addr, sizeof(*addr));

	if (prefered || valid) {
		struct ifa_cacheinfo ci;
		ci.ifa_prefered = prefered;
		ci.ifa_valid = valid;
		ci.cstamp = 0;
		ci.tstamp = 0;
		addattr_l(n, sizeof(buf), IFA_CACHEINFO, &ci, sizeof(ci));
	}
	return rtnl_route_do(n, NULL);
}

int addr_add(const struct in6_addr *addr, uint8_t plen,
	     uint8_t flags, uint8_t scope, int ifindex,
	     uint32_t prefered, uint32_t valid)
{
	return addr_mod(RTM_NEWADDR, NLM_F_CREATE|NLM_F_REPLACE,
			addr, plen, flags, scope, ifindex, prefered, valid);
}

int addr_del(const struct in6_addr *addr, uint8_t plen, int ifindex)
{
	return addr_mod(RTM_DELADDR, 0, addr, plen, 0, 0, ifindex, 0, 0);
}

/* addr4_mod: helper function for addr4_* functions */
static int addr4_mod(const struct in_addr *addr, int plen4, int ifindex, int cmd)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[256];
	} req;
	struct list_head *list;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = plen4;
	req.ifa.ifa_index = ifindex;
	addattr_l(&req.n, sizeof(req), IFA_LOCAL, addr, sizeof(struct in_addr));

	if (rtnl_open(&rth, 0) != 0)
		return -1;

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0) {
		RTDBG("Failed to modify address");
		close(rth.fd);
		return -1;
	}

	close(rth.fd);
	return 0;
}

/**
 * daddr4_del:
 * @addr: IP address
 * @plen4: prefix length
 * @ifindex: network device index
 *
 * Remove IP address @addr/plen4 from device @ifindex.
 *
 * Returns: 0 if successful, else -1
 */
int addr4_del(const struct in_addr *addr, uint8_t plen4, int ifindex)
{
	return addr4_mod(addr, plen4, ifindex, RTM_DELADDR);
}

/**
 * addr4_add:
 * @addr: IP address
 * @plen4: IP address prefix length
 * @ifindex: network device index
 *
 * Add IP address @addr to device @ifindex.
 *
 * Returns: 0 if successful, else -1
 */
int addr4_add(const struct in_addr *addr, uint8_t plen4, int ifindex)
{
	return addr4_mod(addr, plen4, ifindex, RTM_NEWADDR);
}

int prefix_add(int ifindex, const struct nd_opt_prefix_info *pinfo)
{
	uint8_t buf[128];
	struct nlmsghdr *n;
	struct prefixmsg *pfxm;
	struct prefix_cacheinfo ci;

	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct prefixmsg));
	n->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE;
	n->nlmsg_type = RTM_NEWPREFIX;

	pfxm = NLMSG_DATA(n);
	pfxm->prefix_family = AF_INET6;
	pfxm->prefix_ifindex = ifindex;
	pfxm->prefix_type = pinfo->nd_opt_pi_type;
	pfxm->prefix_len = pinfo->nd_opt_pi_prefix_len;
	pfxm->prefix_flags = pinfo->nd_opt_pi_flags_reserved;

	addattr_l(n, sizeof(buf), PREFIX_ADDRESS, &pinfo->nd_opt_pi_prefix,
		  sizeof(struct in6_addr));
	memset(&ci, 0, sizeof(ci));
	/* pinfo lifetimes stored locally in host byte order */
	ci.valid_time = htonl(pinfo->nd_opt_pi_valid_time);
	ci.preferred_time = htonl(pinfo->nd_opt_pi_preferred_time);
	addattr_l(n, sizeof(buf), PREFIX_CACHEINFO, &ci, sizeof(ci));

	return rtnl_route_do(n, NULL);
}

static int route_mod(int cmd, int oif, uint8_t table, uint8_t proto,
		     unsigned flags, uint32_t priority,
		     const struct in6_addr *src, int src_plen,
		     const struct in6_addr *dst, int dst_plen,
		     const struct in6_addr *gateway)
{
	uint8_t buf[512];
	struct nlmsghdr *n;
	struct rtmsg *rtm;

	if (cmd == RTM_NEWROUTE && oif == 0)
		return -1;

	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;

	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	n->nlmsg_flags = NLM_F_REQUEST;
	if (cmd == RTM_NEWROUTE) {
		n->nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
	}
	n->nlmsg_type = cmd;

	rtm = NLMSG_DATA(n);
	rtm->rtm_family = AF_INET6;
	rtm->rtm_dst_len = dst_plen;
	rtm->rtm_src_len = src_plen;
	rtm->rtm_table = table;
	rtm->rtm_protocol = proto;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_flags = flags;

	addattr_l(n, sizeof(buf), RTA_DST, dst, sizeof(*dst));
	if (src)
		addattr_l(n, sizeof(buf), RTA_SRC, src, sizeof(*src));
	addattr32(n, sizeof(buf), RTA_OIF, oif);
	if (gateway)
		addattr_l(n, sizeof(buf),
			  RTA_GATEWAY, gateway, sizeof(*gateway));
	if (priority)
		addattr32(n, sizeof(buf), RTA_PRIORITY, priority);
	return rtnl_route_do(n, NULL);
}


/**
 * route_add - add route to kernel routing table
 * @oif: outgoing interface
 * @table: routing table number
 * @metric: route preference
 * @src: source prefix
 * @src_plen: source prefix length
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 * @gateway: possible gateway
 *
 * Adds a new route through interface @oif, with source
 * @src/@src_plen, to destinations specified by @dst/@dst_plen.  Route
 * will be added to routing table number @table.  Returns zero on
 * success, negative otherwise.
 **/
int route_add(int oif, uint8_t table, uint8_t proto,
	      unsigned flags, uint32_t metric,
	      const struct in6_addr *src, int src_plen,
	      const struct in6_addr *dst, int dst_plen,
	      const struct in6_addr *gateway)
{
	return route_mod(RTM_NEWROUTE, oif, table, proto, flags,
			 metric, src, src_plen, dst, dst_plen, gateway);
}

/**
 * route_del - delete route from kernel routing table
 * @oif: outgoing interface
 * @table: routing table number
 * @metric: route preference
 * @src: source prefix
 * @src_plen: source prefix length
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 * @gateway: possible gateway
 *
 * Deletes an entry with @src/@src_plen as source and @dst/@dst_plen
 * as destination, through interface @oif, from the routing table
 * number @table.
 **/
int route_del(int oif, uint8_t table, uint32_t metric,
	      const struct in6_addr *src, int src_plen,
	      const struct in6_addr *dst, int dst_plen,
	      const struct in6_addr *gateway)
{
	return route_mod(RTM_DELROUTE, oif, table, RTPROT_UNSPEC,
			 0, metric, src, src_plen, dst, dst_plen, gateway);
}

static int rule_mod(const char *iface, int cmd, uint8_t table,
		    uint32_t priority, uint8_t action,
		    const struct in6_addr *src, int src_plen,
		    const struct in6_addr *dst, int dst_plen, int flags)
{
	uint8_t buf[512];
	struct nlmsghdr *n;
	struct rtmsg *rtm;

	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;

	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	n->nlmsg_flags = NLM_F_REQUEST;
	if (cmd == RTM_NEWRULE) {
		n->nlmsg_flags |= NLM_F_CREATE;
	}
	n->nlmsg_type = cmd;

	rtm = NLMSG_DATA(n);
	rtm->rtm_family = AF_INET6;
	rtm->rtm_dst_len = dst_plen;
	rtm->rtm_src_len = src_plen;
	rtm->rtm_table = table;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = action;
	rtm->rtm_flags = flags;

	addattr_l(n, sizeof(buf), RTA_DST, dst, sizeof(*dst));
	if (src)
		addattr_l(n, sizeof(buf), RTA_SRC, src, sizeof(*src));
	if (priority)
		addattr32(n, sizeof(buf), RTA_PRIORITY, priority);
	if (iface)
		addattr_l(n, sizeof(buf), RTA_IIF, iface, strlen(iface) + 1);

	return rtnl_route_do(n, NULL);
}

/**
 * rule_add - add rule for routes
 * @src: source prefix
 * @src_plen: source prefix length
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 *
 * Add routing rule for routes with @src/@src_plen source and
 * @dst/@dst_plen destination.  Returns table number on success,
 * negative otherwise.
 **/
int rule_add(const char *iface, uint8_t table,
	     uint32_t priority, uint8_t action,
	     const struct in6_addr *src, int src_plen,
	     const struct in6_addr *dst, int dst_plen, int flags)
{
	return rule_mod(iface, RTM_NEWRULE, table,
			priority, action,
			src, src_plen, dst, dst_plen, flags);
}


/**
 * rule_del - delete rule for routes
 * @src: source prefix
 * @src_plen: source prefix length
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 *
 * Deletes routing rule for routes with @src/@src_plen source and
 * @dst/@dst_plen destination.  Returns zero on success, negative
 * otherwise.
 **/
int rule_del(const char *iface, uint8_t table,
	     uint32_t priority, uint8_t action,
	     const struct in6_addr *src, int src_plen,
	     const struct in6_addr *dst, int dst_plen, int flags)
{
	return rule_mod(iface, RTM_DELRULE, table,
			priority, action,
			src, src_plen, dst, dst_plen, flags);
}

/* generic routing rule help function for rule4_add() and
 * rule4_del() */
static int change_iprule(int cmd, int type, const struct in_addr *src, int src_plen,
			 const struct in_addr *dst, int dst_plen, int table,
			 const char *device, int prio, int flags)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_type = cmd;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.r.rtm_family = AF_INET;
	req.r.rtm_protocol = RTPROT_BOOT;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_table = 0;
	req.r.rtm_type = type;
	req.r.rtm_flags = flags;

	if (cmd == RTM_NEWRULE) {
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	}

	if (src != NULL) {
		req.r.rtm_src_len = src_plen; /* bits */
		addattr_l(&req.n, sizeof(req), RTA_SRC, (void *) src,
			  sizeof(struct in_addr));
	}

	if (dst != NULL) {
		req.r.rtm_dst_len = dst_plen; /* bits */
		addattr_l(&req.n, sizeof(req), RTA_DST, (void *) dst,
			  sizeof(struct in_addr));
	}

	if (table < 0 || table > 255) {
		RTDBG("change_iprule: invalid table id %i\n", table);
		return -1;
	}
	req.r.rtm_table = table;

	if (prio >= 0) {
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, prio);
	}

	if (device != NULL) {
		/* Use also the incoming device to distinct packages */
		addattr_l(&req.n, sizeof(req), RTA_IIF, device,
			  strlen(device) + 1);
	}

	if (rtnl_open(&rth, 0) != 0)
		return -1;

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0) {
		RTDBG("change_iprule: rtnl_talk failed\n");
		close(rth.fd);
		return -1;
	}

	close(rth.fd);
	return 0;
}

/**
 * rule4_add - add rule for IPv4 routes
 * @src: source prefix
 * @src_plen: source prefix length
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 *
 * Deletes routing rule for routes with @src/@src_plen source and
 * @dst/@dst_plen destination.  Returns zero on success, negative
 * otherwise.
 **/
int rule4_add(const char *iface, uint8_t table,
	     uint32_t priority, uint8_t action,
	     const struct in_addr *src, int src_plen,
	     const struct in_addr *dst, int dst_plen, int flags)
{
	return change_iprule(RTM_NEWRULE, action, src, src_plen, dst, dst_plen, table, iface,
			priority, flags);
}

/**
 * rule4_del - delete rule for IPv4 routes
 * @src: source prefix
 * @src_plen: source prefix length
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 *
 * Deletes routing rule for routes with @src/@src_plen source and
 * @dst/@dst_plen destination.  Returns zero on success, negative
 * otherwise.
 **/
int rule4_del(const char *iface, uint8_t table,
	     uint32_t priority, uint8_t action,
	     const struct in_addr *src, int src_plen,
	     const struct in_addr *dst, int dst_plen, int flags)
{
	return change_iprule(RTM_DELRULE, action, src, src_plen, dst, dst_plen, table, iface,
				priority, flags);
}

/**
 * route4_mod - delete or add route
 * @cmd:
 * @oif: outgoing interface
 * @table: routing table number
 * @flags:
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 * @gateway: possible gateway
 *
 **/
static int route4_mod(int cmd, int oif, uint8_t table, unsigned flags,
			 const struct in_addr *src, int src_plen,
		     const struct in_addr *dst, int dst_plen,
		     const struct in_addr *gateway)
{

	struct rtnl_handle rth;
	struct rtrequest {
		struct nlmsghdr n;
		struct rtmsg r;
		char payload[256];
	} rtreq;

	memset(&rtreq, 0, sizeof(rtreq));

	if (cmd == RTM_NEWROUTE && oif == 0)
		return -1;

	if (rtnl_open(&rth, 0) != 0)
		return -1;

	rtreq.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	rtreq.n.nlmsg_flags = NLM_F_REQUEST;
	rtreq.n.nlmsg_type = cmd;
	if (cmd == RTM_NEWROUTE) {
		rtreq.n.nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
	}
	if (gateway) rtreq.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;// | NLM_F_EXCL;


	rtreq.r.rtm_family = AF_INET;
	rtreq.r.rtm_table = table;
	if (cmd == RTM_DELROUTE) {
		rtreq.r.rtm_protocol = RTPROT_UNSPEC;
		rtreq.r.rtm_scope = RT_SCOPE_NOWHERE;
		rtreq.r.rtm_type = RTN_UNSPEC;
	} else {
		rtreq.r.rtm_protocol = RTPROT_BOOT;
		rtreq.r.rtm_scope = RT_SCOPE_LINK;
		rtreq.r.rtm_type = RTN_UNICAST;
	}

	if (dst) {
	addattr_l(&rtreq.n, sizeof(rtreq), RTA_DST, dst, sizeof(*dst));
	rtreq.r.rtm_dst_len = dst_plen;
	}
	addattr32(&rtreq.n, sizeof(rtreq), RTA_OIF, oif);

	if (src) {
	addattr_l(&rtreq.n, sizeof(rtreq), RTA_SRC, src, sizeof(*src));
	rtreq.r.rtm_src_len = src_plen;
	}
	addattr32(&rtreq.n, sizeof(rtreq), RTA_OIF, oif);

	if (gateway) {
		addattr_l(&rtreq.n, sizeof(rtreq), RTA_GATEWAY, gateway, sizeof(*gateway));
		rtreq.r.rtm_scope = RT_SCOPE_UNIVERSE;
	}

	if (rtnl_talk(&rth, &rtreq.n, 0, 0, NULL, NULL, NULL) < 0)
		RTDBG("route already setup \n");
	else {
		RTDBG("route modification succeeded\n");
	}
	close(rth.fd);
	return 0;
}

/**
 * route4_add - add route to kernel routing table
 * @oif: outgoing interface
 * @table: routing table number
 * @flags:
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 * @gateway: possible gateway
 *
 * Adds a new route through interface @oif, with source
 * @src/@src_plen, to destinations specified by @dst/@dst_plen.  Route
 * will be added to routing table number @table.  Returns zero on
 * success, negative otherwise.
 **/
int route4_add(int oif, uint8_t table, unsigned flags,
		  const struct in_addr *src, int src_plen,
	      const struct in_addr *dst, int dst_plen,
	      const struct in_addr *gateway)
{
	return route4_mod(RTM_NEWROUTE, oif, table, flags, src, src_plen, dst, dst_plen, gateway);
}

/**
 * route4_del - delete route from kernel routing table
 * @oif: outgoing interface
 * @table: routing table number
 * @dst: destination prefix
 * @dst_plen: destination prefix length
 * @gateway: possible gateway
 *
 * Deletes an entry with @src/@src_plen as source and @dst/@dst_plen
 * as destination, through interface @oif, from the routing table
 * number @table.
 **/

int route4_del(int oif, uint8_t table,
		  const struct in_addr *src, int src_plen,
		  const struct in_addr *dst, int dst_plen,
	      const struct in_addr *gateway)
{
	return route4_mod(RTM_DELROUTE, oif, table, 0, src, src_plen, dst, dst_plen, gateway);
}

int rtnl_iterate(int proto, int type, rtnl_filter_t func, void *extarg)
{
	struct rtnl_handle rth;

	if (rtnl_open_byproto(&rth, 0, proto) < 0)
		return -1;

	if (rtnl_wilddump_request(&rth, AF_INET6, type) < 0) {
		rtnl_close(&rth);
		return -1;
	}

	if (rtnl_dump_filter(&rth, func, extarg, NULL, NULL) < 0) {
		rtnl_close(&rth);
		return -1;
	}

	rtnl_close(&rth);

	return 0;
}
