/*
 * $Id: ha.c 1.99 06/01/22 13:56:55+09:00 nakam@linux-ipv6.org $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 * 
 * Author: Antti Tuominen <anttit@tcs.hut.fi>
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
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>
#ifndef HAVE_MIP6_ICMP6_H
#include <netinet-icmp6.h>
#endif
#ifdef HAVE_NETINET_IP6MH_H
#include <netinet/ip6mh.h>
#else
#include <netinet-ip6mh.h>
#endif
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/if_tunnel.h>

#include "debug.h"
#include "icmp6.h"
#include "mpdisc_ha.h"
#include "mh.h"
#include "tqueue.h"
#include "bcache.h"
#include "util.h"
#include "cn.h"
#include "retrout.h"
#include "tunnelctl.h"
#include "rtnl.h"
#include "ha.h"
#include "dhaad_ha.h"
#include "conf.h"
#ifdef ENABLE_VT
#include "vt.h"
#endif
#include "ipsec.h"
#include "xfrm.h"
#include "ndisc.h"
#include "prefix.h"

#ifndef IPV6_JOIN_ANYCAST
#define IPV6_JOIN_ANYCAST	27
#endif

static pthread_mutex_t bu_worker_mutex;
static volatile unsigned long bu_worker_count = 0;
static pthread_cond_t cond;

LIST_HEAD(bu_worker_list);
LIST_HEAD(ha_interfaces);

static void ha_recv_ra(const struct icmp6_hdr *ih, 
		       const ssize_t len,
		       const struct in6_addr *src,
		       const struct in6_addr *dst,
		       const int iif,
		       const int hoplimit)
{
	struct nd_router_advert *ra = (struct nd_router_advert *)ih;
	int optlen = len - sizeof(struct nd_router_advert);
	uint8_t *opt;
	struct nd_opt_prefix_info *pinfo[MAX_HOME_AGENTS];
	int i, num_pinfo = 0;
	struct ha_interface *iface;
	uint16_t pref = 0;
	uint16_t life = 0;

	/* validity checks */
	if (hoplimit < 255 || !IN6_IS_ADDR_LINKLOCAL(src) ||
	    ih->icmp6_code != 0 || len < sizeof(struct nd_router_advert) ||
	    !conf.pmgr.accept_ra(iif, src, dst, ra))
		return;

	if ((iface = ha_get_if(iif)) == NULL)
	    return;

	opt = (uint8_t *)(ra + 1);

	mpd_handle_mpa_flags(iface, ra->nd_ra_flags_reserved);

	if (ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT) {
		life = ntohs(ra->nd_ra_router_lifetime);
	}
	while (optlen > 1 && num_pinfo < MAX_HOME_AGENTS) {
		int olen = opt[1] << 3;

		if (olen > optlen || olen == 0)
			return;

		if (opt[0] == ND_OPT_PREFIX_INFORMATION) {
			struct nd_opt_prefix_info *p;
			p = (struct nd_opt_prefix_info *)opt;
			if (p->nd_opt_pi_prefix_len > 128)
				return;
			p->nd_opt_pi_valid_time = 
				ntohl(p->nd_opt_pi_valid_time);
			p->nd_opt_pi_preferred_time =
				ntohl(p->nd_opt_pi_preferred_time);

			/* XXX: Limitation: timespec cannot handle
			 * unsigned long value; To avoid overflow,
			 * valid/preferred lifetime are decresed and fake it
			 * like they are received such value.
			 * Todo: fix it correctly!
			 */
			p->nd_opt_pi_valid_time = umin(p->nd_opt_pi_valid_time,
						       0x7fffffff);
			p->nd_opt_pi_preferred_time = umin(p->nd_opt_pi_preferred_time,
							   0x7fffffff);

			if (ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT)
				mpd_handle_pinfo(iface, p);
			pinfo[num_pinfo++] = p;
		} else if (opt[0] == ND_OPT_HOME_AGENT_INFO &&
			   ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT) {
			struct nd_opt_homeagent_info *hainfo;
			hainfo = (struct nd_opt_homeagent_info *)opt;
			pref = ntohs(hainfo->nd_opt_hai_preference);
			life = ntohs(hainfo->nd_opt_hai_lifetime);
		}
		optlen -= olen;
		opt += olen;
	}
	for (i = 0; i < num_pinfo; i++) {
		/* if the router is running as HA, add it, else delete it */
		if (pinfo[i]->nd_opt_pi_flags_reserved & 
		    ND_OPT_PI_FLAG_RADDR) {
			dhaad_insert_halist(iface, pref, life,
					    pinfo[i], src);
		}
	}
	mpd_del_expired_pinfos(iface);
}

struct icmp6_handler ha_ra_handler = {
	.recv = ha_recv_ra,
};

struct ha_interface *ha_get_if(const int ifindex)
{
	struct list_head *lp;

	list_for_each(lp, &ha_interfaces) {
		struct ha_interface *iface;

		iface = list_entry(lp, struct ha_interface, iflist);
		if (iface->ifindex == ifindex)
			return iface;
	}
	return NULL;
}

struct ha_interface *ha_get_if_by_addr(const struct in6_addr *addr)
{
	struct list_head *li;

	list_for_each(li, &ha_interfaces) {
		struct ha_interface *iface;
		struct list_head *la;

		iface = list_entry(li, struct ha_interface, iflist);

		list_for_each(la, &iface->addr_list) {
			struct ha_addr_holder *addrs;
			addrs = list_entry(la, struct ha_addr_holder, list);
			if (IN6_ARE_ADDR_EQUAL(&addrs->ha_addr, addr))
				return iface;
		}
	}
	return NULL;
}

struct ha_interface *ha_get_if_by_anycast(const struct in6_addr *anycast,
					  struct in6_addr **addrp)
{
	struct list_head *li;

	list_for_each(li, &ha_interfaces) {
		struct ha_interface *iface;
		struct list_head *la;

		iface = list_entry(li, struct ha_interface, iflist);

		list_for_each(la, &iface->addr_list) {
			struct ha_addr_holder *addrs;
			addrs = list_entry(la, struct ha_addr_holder, list);
			if (IN6_ARE_ADDR_EQUAL(&addrs->anycast_addr,
					       anycast)) {
				if (addrp)
					*addrp = &addrs->ha_addr;
				return iface;
			}
		}
	}
	return NULL;
}

static int ha_if_addr_setup(struct sockaddr_nl *who,
			    struct nlmsghdr *n,
			    void *arg)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(n);
	struct ha_interface *i = (struct ha_interface *)arg;
	struct ha_addr_holder *addr; 
	struct rtattr * rta_tb[IFA_MAX+1];

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
		return -1;

	if (n->nlmsg_type != RTM_NEWADDR)
		return 0;
	if (ifa->ifa_index != i->ifindex)
		return 0;
	if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
		return 0;

	memset(rta_tb, 0, sizeof(rta_tb));
	parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa), 
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

	if (!rta_tb[IFA_ADDRESS])
		return 0;

	addr = malloc(sizeof(*addr));
	if (addr != NULL) {
		struct in6_addr *ha_addr = RTA_DATA(rta_tb[IFA_ADDRESS]);

		addr->ha_addr = *ha_addr;

		dhaad_gen_ha_anycast(&addr->anycast_addr,
				     ha_addr, ifa->ifa_prefixlen);
				     
		if (if_mc_group(ICMP6_MAIN_SOCK, i->ifindex,
				&addr->anycast_addr, IPV6_JOIN_ANYCAST) < 0)
			return -1;
		dbg("Joined anycast group "
		    "%x:%x:%x:%x:%x:%x:%x:%x on iface %d\n",
		    NIP6ADDR(&addr->anycast_addr), i->ifindex);
		list_add_tail(&addr->list, &i->addr_list);
	}
	return 0;
}

int ha_addr_setup(void)
{
	struct list_head *lp;
	list_for_each(lp, &ha_interfaces) {
		struct ha_interface *i;
		i = list_entry(lp, struct ha_interface, iflist);
		if (addrs_iterate(ha_if_addr_setup, i) < 0)
			return -1;
		if (if_mc_group(ICMP6_MAIN_SOCK, i->ifindex,
				&in6addr_all_nodes_mc, IPV6_JOIN_GROUP) < 0)
			return -1;
	}
	return 0;
}

static int ha_insert_if(int newifindex)
{
	struct ha_interface *newif;

	newif = malloc(sizeof(*newif));
	if (newif == NULL)
		return -ENOMEM;

	memset(newif, 0, sizeof(*newif));
	newif->ifindex = newifindex;
	INIT_LIST_HEAD(&newif->ha_list);
	INIT_LIST_HEAD(&newif->addr_list);
	INIT_LIST_HEAD(&newif->prefix_list);
	list_add_tail(&newif->iflist, &ha_interfaces);
	return 0;
}

int homeagent_if_init(int ifindex)
{
	if (ifindex == 0)
		return -1;
	ha_insert_if(ifindex);
	return 0;
}

int homeagents_ifall_init(void)
{
	struct if_nameindex *ifs, *i;

	if (!list_empty(&ha_interfaces)) return 0;

	ifs = if_nameindex();
	for (i = ifs; i->if_index != 0; i++) {
		if (i->if_index != 1) {
			ha_insert_if(i->if_index);
		}
	}
	if_freenameindex(ifs);

	return 0;
}

#ifdef ENABLE_VT
struct ha_vt_arg {
	const struct vt_handle *vh;
};

static int ha_halist_vt_dump(int ifindex, void *data, void *arg)
{
	struct home_agent *h = (struct home_agent *)data;
	struct ha_vt_arg *hva = (struct ha_vt_arg *)arg;
	const struct vt_handle *vh = hva->vh;
	char buf[IF_NAMESIZE + 1];
	char *dev;

	if (!h)
		return 0;

	dev = if_indextoname(ifindex, buf);
	if (!dev || strlen(dev) == 0)
		vt_printf(vh, "(%d)", h->iface->ifindex);
	else
		vt_printf(vh, "%s", dev);

	vt_printf(vh, " ");

	vt_printf_bl(vh, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(&h->addr));

	vt_printf(vh, "\n");

	vt_printf(vh, " preference %d", h->preference);

	vt_printf(vh, " lifetime %lu", h->lifetime);

	vt_printf(vh, "\n");

	return 0;
}

/**
 * ha_halist_iterate - apply function to every home agent list entry
 * @func: function to apply
 * @arg: extra data for @func
 **/
static void ha_halist_iterate(int (* func)(int, void *, void *), void *arg)
{
	struct list_head *lp;

	list_for_each(lp, &ha_interfaces) {
		struct ha_interface *iface;

		iface = list_entry(lp, struct ha_interface, iflist);

		dhaad_halist_iterate(iface, func, arg);
	}
}

static int ha_plist_vt_dump(int ifindex, void *data, void *arg)
{
	struct prefix_list_entry *ple = (struct prefix_list_entry *)data;
	struct ha_vt_arg *hva = (struct ha_vt_arg *)arg;
	const struct vt_handle *vh = hva->vh;
	char buf[IF_NAMESIZE + 1];
	char *dev;
	struct timespec ts_now;

	if (!ple)
		return 0;

	dev = if_indextoname(ifindex, buf);
	if (!dev || strlen(dev) == 0)
		vt_printf(vh, "(%d)", ifindex);
	else
		vt_printf(vh, "%s", dev);

	vt_printf(vh, " ");

	vt_printf_bl(vh, "%x:%x:%x:%x:%x:%x:%x:%x/%u",
		     NIP6ADDR(&ple->ple_prefix), ple->ple_plen);

	vt_printf(vh, "\n");

	vt_printf(vh, " valid ");
	if (clock_gettime(CLOCK_REALTIME, &ts_now) != 0)
		vt_printf(vh, "(error)");
	else {
		if (tsafter(ts_now, ple->timestamp))
			vt_printf(vh, "(broken)");
		else {
			uint32_t valid = ple->ple_valid_time;
			uint32_t alives;
			struct timespec ts;

			tssub(ts_now, ple->timestamp, ts);
			/* "ts" is now time how log it alives */
			alives = ts.tv_sec;

			if (alives > valid) {
				vt_printf(vh, "-%lu", alives - valid);
			} else {
				vt_printf(vh, "%lu", valid - alives);
			}
		}
	}
	vt_printf(vh, " / %lu", ple->ple_valid_time);

	vt_printf(vh, " preferred %lu", ple->ple_prefd_time);

	vt_printf(vh, " flags %c%c%c",
		  ((ple->ple_flags & ND_OPT_PI_FLAG_ONLINK) ? 'O' : '-'),
		  ((ple->ple_flags & ND_OPT_PI_FLAG_AUTO) ? 'A' : '-'),
		  ((ple->ple_flags & ND_OPT_PI_FLAG_RADDR) ? 'R' : '-'));

	vt_printf(vh, "\n");

	return 0;
}

/**
 * ha_plist_iterate - apply function to every prefix list entry
 * @func: function to apply
 * @arg: extra data for @func
 **/
static void ha_plist_iterate(int (* func)(int, void *, void *), void *arg)
{
	struct list_head *lp;

	list_for_each(lp, &ha_interfaces) {
		struct ha_interface *iface;

		iface = list_entry(lp, struct ha_interface, iflist);

		mpd_plist_iterate(iface, func, arg);
	}
}

static int ha_thread_vt_cmd(const struct vt_handle *vh, const char *str)
{
	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}
	pthread_mutex_lock(&bu_worker_mutex);
	vt_printf(vh, "bu: %lu\n", bu_worker_count);
	pthread_mutex_unlock(&bu_worker_mutex);
	return 0;
}

static int ha_halist_vt_cmd(const struct vt_handle *vh, const char *str)
{
	struct ha_vt_arg hva;
	hva.vh = vh;
	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}
	ha_halist_iterate(ha_halist_vt_dump, &hva);
	return 0;
}

static int ha_plist_vt_cmd(const struct vt_handle *vh, const char *str)
{
	struct ha_vt_arg hva;
	hva.vh = vh;
	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}
	ha_plist_iterate(ha_plist_vt_dump, &hva);
	return 0;
}

static struct vt_cmd_entry vt_cmd_thread = {
	.cmd = "thread",
	.parser = ha_thread_vt_cmd,
};

static struct vt_cmd_entry vt_cmd_hal = {
	.cmd = "hal",
	.parser = ha_halist_vt_cmd,
};

static struct vt_cmd_entry vt_cmd_pl = {
	.cmd = "pl",
	.parser = ha_plist_vt_cmd,
};

static int ha_vt_init(void)
{
	int ret;
	vt_cmd_init(&vt_cmd_thread);
	ret = vt_cmd_add_root(&vt_cmd_thread);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_hal);
	ret = vt_cmd_add_root(&vt_cmd_hal);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_pl);
	ret = vt_cmd_add_root(&vt_cmd_pl);
	return ret;
}
#endif

struct home_tnl_ops_parm {
	struct bcentry *bce;
	int ba_status;
};

static int home_tnl_del(int old_if, int new_if, struct home_tnl_ops_parm *p)
{
	const struct in6_addr *our_addr, *peer_addr, *coa, *old_coa;

	assert(old_if);

	our_addr = &p->bce->our_addr;
	peer_addr = &p->bce->peer_addr;
	coa = &p->bce->peer_addr;
	old_coa = &p->bce->coa;

	if (conf.UseMnHaIPsec) {
		/* migrate */ 
		if (ha_ipsec_tnl_update(our_addr, peer_addr, coa, old_coa,
					p->bce->tunnel) < 0) {
			syslog(LOG_ERR, "migrate FAILED\n");
		}
		/* delete SP entry */ 
		if (ha_ipsec_tnl_pol_del(our_addr, peer_addr,
					 p->bce->tunnel) < 0) {
			syslog(LOG_ERR, "add SP etnry FAILED\n");
		}
	}
	/* delete HoA route */
	if (route_del(old_if, RT6_TABLE_MIP6, IP6_RT_PRIO_MIP6_FWD,
		      NULL, 0, peer_addr, 128, NULL) < 0) {
		syslog(LOG_ERR, "route_del failed");
	}
	/* update tunnel interface */
	p->bce->tunnel = new_if;

	return 0;
}

static int home_tnl_add(int old_if, int new_if, struct home_tnl_ops_parm *p)
{
	const struct in6_addr *our_addr, *peer_addr, *coa, *old_coa;

	assert(new_if);

	our_addr = &p->bce->our_addr;
	peer_addr = &p->bce->peer_addr;
	coa = &p->bce->coa;
	old_coa = &p->bce->peer_addr;

	/* update tunnel interface */
	p->bce->tunnel = new_if;

	/* add HoA route */
	if (route_add(new_if, RT6_TABLE_MIP6, IP6_RT_PRIO_MIP6_FWD,
		      NULL, 0, peer_addr, 128, NULL) < 0) {
		p->ba_status = IP6_MH_BAS_INSUFFICIENT;
		goto err;
	}
	/* add SP entry */	
	if (conf.UseMnHaIPsec) {
		if (ha_ipsec_tnl_pol_add(our_addr, peer_addr,
					 p->bce->tunnel) < 0) {
			p->ba_status = IP6_MH_BAS_INSUFFICIENT;
			goto err;
		}
		/* migrate */ 
		if (ha_ipsec_tnl_update(our_addr, peer_addr, coa, old_coa,
					p->bce->tunnel) < 0) {
			syslog(LOG_ERR, "migrate FAILED\n");
			p->ba_status = IP6_MH_BAS_INSUFFICIENT;
			goto err;
		}
	}
	return 0;
err:
	home_tnl_del(new_if, old_if, p);
	return -1;
}

static int home_tnl_chg(int old_if, int new_if, struct home_tnl_ops_parm *p)
{
	assert(old_if && new_if);

	if (old_if == new_if) {
		const struct in6_addr *our_addr, *peer_addr, *coa, *old_coa;

		our_addr = &p->bce->our_addr;
		peer_addr = &p->bce->peer_addr;
		coa = &p->bce->coa;
		old_coa = &p->bce->old_coa;

		/* migrate */ 
		if (conf.UseMnHaIPsec &&
		    !IN6_ARE_ADDR_EQUAL(old_coa, coa) &&
		    ha_ipsec_tnl_update(our_addr, peer_addr, coa, old_coa,
					p->bce->tunnel) < 0) {
			syslog(LOG_ERR, "migrate FAILED\n");
			return -1;
		}
	} else { 
		home_tnl_del(old_if, new_if, p);
		if (home_tnl_add(old_if, new_if, p) < 0)
			return -1;
	}
	return 0;
}

static int home_tnl_ops(int request, int old_if, int new_if, void *data)
{
	struct home_tnl_ops_parm *p = data;
	int res = -1;

	if (request == SIOCADDTUNNEL)
		res = home_tnl_add(old_if, new_if, p);
	else if (request == SIOCCHGTUNNEL)
		res = home_tnl_chg(old_if, new_if, p);
	else if (request == SIOCDELTUNNEL)
		res = home_tnl_del(old_if, new_if, p);
	return res;
}

static void home_cleanup(struct bcentry *bce)
{
	mpd_cancel_mpa(&bce->our_addr, &bce->peer_addr);

	if (bce->link > 0) {
		route_del(bce->link, RT6_TABLE_MIP6, IP6_RT_PRIO_MIP6_OUT,
			  &bce->our_addr, 128, &bce->peer_addr, 128, NULL);
		proxy_nd_stop(bce->link, &bce->peer_addr, bce->flags);
	}
	if (bce->tunnel > 0) {
		struct home_tnl_ops_parm p = {
			.bce = bce,
			.ba_status = IP6_MH_BAS_ACCEPTED
		};
		tunnel_del(bce->tunnel, home_tnl_ops, &p);
	}
	if (conf.UseMnHaIPsec) {
		ha_mn_ipsec_pol_mod(&bce->our_addr, &bce->peer_addr, 0);
	}
}

struct ha_recv_bu_args {
	struct list_head list;
	struct in6_addr src;
	struct in6_addr dst;
	struct in6_addr remote_coa;
	struct in6_addr bind_coa;
	struct ip6_mh_binding_update *bu;
	struct mh_options mh_opts;
	struct timespec lft;
	int iif;
};

static void *ha_recv_bu_worker(void *varg)
{
	struct ha_recv_bu_args *arg = varg;
	struct in6_addr_bundle out;
	struct bcentry *bce = NULL;
	struct timespec lft, tmp;
	int iif;
	uint16_t bu_flags, seqno;
	int status, new = 0;
	int home_ifindex;
	uint8_t ba_flags = 0;
	struct home_tnl_ops_parm p;
restart:	
	lft = arg->lft;
	iif = arg->iif;
	bu_flags = arg->bu->ip6mhbu_flags;
	seqno = ntohs(arg->bu->ip6mhbu_seqno);
	out.src = &arg->src;
	out.dst = &arg->dst;
	if (!IN6_IS_ADDR_UNSPECIFIED(&arg->remote_coa))
		out.remote_coa = &arg->remote_coa;
	else
		out.remote_coa = NULL;
	if (!IN6_IS_ADDR_UNSPECIFIED(&arg->bind_coa))
		out.bind_coa = &arg->bind_coa;
	else
		out.bind_coa = NULL;
	out.local_coa = NULL;

	bce = bcache_get(&arg->src, &arg->dst);
	if (bce) {
		if (bce->type != BCE_NONCE_BLOCK) {
			if (!(bce->flags & IP6_MH_BU_HOME)) {
				/* H-bit mismatch, flags changed */
				bcache_release_entry(bce);
				bce = NULL;
				status = IP6_MH_BAS_REG_NOT_ALLOWED;
				goto send_nack;
			}
			if (bce->type == BCE_DAD) {
				bcache_release_entry(bce);
				pthread_mutex_lock(&bu_worker_mutex);
				list_add_tail(&arg->list, &bu_worker_list);
				bu_worker_count--;
				/* with BCE_DAD we should have at least one
				   active worker */
				assert(bu_worker_count > 0);
				pthread_mutex_unlock(&bu_worker_mutex);
				return NULL;
			}
			if (!MIP6_SEQ_GT(seqno, bce->seqno)) {
				/* sequence number expired */
				status = IP6_MH_BAS_SEQNO_BAD;
				seqno = bce->seqno;
				bcache_release_entry(bce);
				bce = NULL;
				goto send_nack;
			}
		} else {
			bcache_release_entry(bce);
			bce = NULL;
			/* don't let MN deregister BCE_NONCE_BLOCK entry */
			if (!tsisset(lft)) {
				status = IP6_MH_BAS_UNSPECIFIED;
				goto send_nack;
			}
			/* else get rid of it */
			bcache_delete(&arg->src, &arg->dst);
		}
	} else if (!tsisset(lft)) {
		status = IP6_MH_BAS_NOT_HA;
		goto send_nack;
	}
	status = conf.pmgr.discard_binding(&out, arg->bu, &arg->mh_opts);
	if (status >= IP6_MH_BAS_UNSPECIFIED) {
		goto send_nack;
	}	
	home_ifindex = mpd_prefix_check(&arg->src, &arg->dst, &tmp, new);
	if (home_ifindex <= 0) {
		/* not home agent for this subnet */
		status = IP6_MH_BAS_NOT_HOME_SUBNET;
		goto send_nack;
	}

	/* if prefix is or will be deprecated during the
	 * requested lifetime, ba status 1, else 0 */
	if (tsbefore(lft, tmp)) {
		if (conf.SendMobPfxAdvs)
			status = IP6_MH_BAS_PRFX_DISCOV;
		lft = tmp;
	}
	/* lifetime may be further decreased by local policy */
	conf.pmgr.max_binding_life(&out, arg->bu,
				   &arg->mh_opts, &lft, &tmp);
	if (tsbefore(lft, tmp))
		lft = tmp;

	if (!bce) {
		bce = bcache_alloc(BCE_HOMEREG);
		if (!bce) {
			status = IP6_MH_BAS_INSUFFICIENT;
			goto send_nack;
		}
		bce->our_addr = arg->src;
		bce->peer_addr = arg->dst;
		bce->coa = arg->bind_coa;
		bce->seqno = seqno;
		bce->flags = bu_flags;
		bce->type = BCE_DAD;
		bce->cleanup = NULL;
		bce->link = home_ifindex;

		if (bcache_add_homereg(bce) < 0) {
			free(bce);
			bce = NULL;
			status = IP6_MH_BAS_INSUFFICIENT;
			goto send_nack;
		}
		/* Do DAD for home address */
		if (ndisc_do_dad(home_ifindex, &arg->dst, 
				 bu_flags & IP6_MH_BU_LLOCAL) < 0) {
			bcache_delete(&arg->src, &arg->dst);
			bce = NULL;
			status =  IP6_MH_BAS_DAD_FAILED;
			goto send_nack;
		}
		bce = bcache_get(&arg->src, &arg->dst);
		if (!bce) {
			BUG("BCE deleted before DAD completed!");
			status =  IP6_MH_BAS_UNSPECIFIED;
			goto send_nack;
		}
		new = 1;
	}
	p.bce = bce;
	p.ba_status = status;
	bce->seqno = seqno;
	bce->flags = bu_flags;
	bce->lifetime = lft;
	if (new) {
		if (tunnel_add(&arg->src, &arg->bind_coa, 
			       home_tnl_ops, &p) < 0) {
			syslog(LOG_ERR, "Tunnel creation failed!");
			if (p.ba_status >= IP6_MH_BAS_UNSPECIFIED)
				status = p.ba_status;
			else
				status = IP6_MH_BAS_INSUFFICIENT;
			goto send_nack;
		}
		bce->cleanup = home_cleanup;

		if (route_add(bce->link, RT6_TABLE_MIP6, IP6_RT_PRIO_MIP6_OUT,
			      &bce->our_addr, 128, &bce->peer_addr, 128, 
			      NULL) < 0) {
			status = IP6_MH_BAS_INSUFFICIENT;
			goto send_nack;
		}

		if (proxy_nd_start(bce->link, &arg->dst, &arg->src,
				   bu_flags) < 0) {
			status = IP6_MH_BAS_INSUFFICIENT;
			goto send_nack;
		}
		bce->type = BCE_HOMEREG;
		bcache_complete_homereg(bce);
	} else {
		bce->old_coa = bce->coa;
		bce->coa = arg->bind_coa;
		if (tunnel_mod(bce->tunnel, &arg->src, &arg->bind_coa, 
			       home_tnl_ops, &p) < 0) { 
			syslog(LOG_ERR, "Tunnel modification failed!");
			if (p.ba_status >= IP6_MH_BAS_UNSPECIFIED)
				status = p.ba_status;
			else
				status = IP6_MH_BAS_INSUFFICIENT;
			goto send_nack;
		}
		bcache_update_expire(bce);
	}
	/* bce is always valid here */
	bcache_release_entry(bce);
	if (!tsisset(lft))
		bcache_delete(&arg->src, &arg->dst);

	if ((bu_flags & IP6_MH_BU_KEYM) && conf.pmgr.use_keymgm(&out))
		ba_flags |= IP6_MH_BA_KEYM;

	if (ba_flags & IP6_MH_BA_KEYM) {
		/* FUTURE */
		/* Move the peer endpoint of the key management
		 * protocol connection, if any, to the new care-of
		 * address. For an IKE phase 1 connection, this means
		 * that any IKE packets sent to the peer are sent to
		 * this address, and packets from this address with
		 * the original ISAKMP cookies are accepted. */
	} else {
		/* FUTURE */
		/* Discard key management connections, if any, to the
		 * old care-of address. If the mobile node did not
		 * have a binding before sending this Binding Update,
		 * discard the connections to the home address. */
	}
	mh_send_ba(&out, status, ba_flags, seqno, &lft, NULL, iif);
	if (new)
		mpd_start_mpa(&bce->our_addr, &bce->peer_addr);
out:
	free(arg);
	pthread_mutex_lock(&bu_worker_mutex);
	if (!list_empty(&bu_worker_list)) {
		struct list_head *l = bu_worker_list.next;
		arg = list_entry(l, struct ha_recv_bu_args, list);
		list_del(&arg->list);
		pthread_mutex_unlock(&bu_worker_mutex);
		goto restart;
	}
	if (--bu_worker_count == 0)
		pthread_cond_signal(&cond);
	pthread_mutex_unlock(&bu_worker_mutex);
	return NULL;
send_nack:
	if (bce) {
		bcache_release_entry(bce);
		bcache_delete(&arg->src, &arg->dst);
	}
	mh_send_ba_err(&out, status, 0, seqno, NULL, iif);
	goto out;
}

static void ha_recv_bu(const struct ip6_mh *mh, 
		       const ssize_t len,
		       const struct in6_addr_bundle *in,
		       const int iif)
{
	struct ip6_mh_binding_update *bu;
	struct mh_options mh_opts;
	struct in6_addr_bundle out;
	struct ha_recv_bu_args *arg;
	struct timespec lft;
	pthread_t worker;

	bu = (struct ip6_mh_binding_update *)mh;

	if (!(bu->ip6mhbu_flags & IP6_MH_BU_HOME))
		cn_recv_bu(mh, len, in, iif);

	if (mh_bu_parse(bu, len, in, &out, &mh_opts, &lft, NULL) < 0)
		return;

	arg = malloc(sizeof(struct ha_recv_bu_args) + len);
	if (!arg) {
		if (bce_exists(out.src, out.dst))
			bcache_delete(out.src, out.dst);
		mh_send_ba_err(&out, IP6_MH_BAS_INSUFFICIENT, 0,
			       ntohs(bu->ip6mhbu_seqno), NULL, iif);
		return;
	}
	arg->src = *out.src;
	arg->dst = *out.dst;
	if (out.remote_coa)
		arg->remote_coa = *out.remote_coa;
	else 
		arg->remote_coa = in6addr_any;
	if (out.bind_coa)
		arg->bind_coa = *out.bind_coa;
	else
		arg->bind_coa = in6addr_any;
	arg->bu = (struct ip6_mh_binding_update *)(arg + 1);
	arg->mh_opts = mh_opts;
	arg->lft = lft;
	arg->iif = iif;
	memcpy(arg + 1, bu, len);

	pthread_mutex_lock(&bu_worker_mutex);
	bu_worker_count++;
	pthread_mutex_unlock(&bu_worker_mutex);

	if (pthread_create(&worker, NULL, ha_recv_bu_worker, arg)) {
		free (arg);
		pthread_mutex_lock(&bu_worker_mutex);
		if (--bu_worker_count == 0)
			pthread_cond_signal(&cond);
		pthread_mutex_unlock(&bu_worker_mutex);
	}
}

static struct mh_handler ha_bu_handler = {
	.recv = ha_recv_bu,
};

int ha_init(void)
{
	pthread_mutexattr_t mattrs;
	pthread_mutexattr_init(&mattrs);
	pthread_mutexattr_settype(&mattrs, PTHREAD_MUTEX_FAST_NP);
	if (pthread_mutex_init(&bu_worker_mutex, &mattrs) ||
	    pthread_cond_init(&cond, NULL))
		return -1;
#ifdef ENABLE_VT
	if (ha_vt_init() < 0)
		return -1;
#endif
	if (homeagents_ifall_init() < 0)
		return -1;
	if (ha_addr_setup() < 0)
		return -1;
	if (dhaad_ha_init() < 0)
		return -1;
	if (mpd_ha_init() < 0)
		return -1;
	if (rule_add(NULL, RT6_TABLE_MIP6,
		     IP6_RULE_PRIO_MIP6_FWD, RTN_UNICAST,
		     &in6addr_any, 0, &in6addr_any, 0) < 0)
		return -1;
	icmp6_handler_reg(ND_ROUTER_ADVERT, &ha_ra_handler);
	mh_handler_reg(IP6_MH_TYPE_BU, &ha_bu_handler);
	return 0;
}

void ha_cleanup(void)
{
	mh_handler_dereg(IP6_MH_TYPE_BU, &ha_bu_handler);
	pthread_mutex_lock(&bu_worker_mutex);
	if (bu_worker_count)
		pthread_cond_wait(&cond, &bu_worker_mutex);
	pthread_mutex_unlock(&bu_worker_mutex);
	bcache_flush();
	icmp6_handler_dereg(ND_ROUTER_ADVERT, &ha_ra_handler);
	rule_del(NULL, RT6_TABLE_MIP6,
		 IP6_RULE_PRIO_MIP6_FWD, RTN_UNICAST,
		 &in6addr_any, 0, &in6addr_any, 0);
	mpd_ha_cleanup();
	dhaad_ha_cleanup();
}
