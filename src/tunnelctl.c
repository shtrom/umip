/*
 * $Id: tunnelctl.c 1.44 06/04/25 13:24:14+03:00 anttit@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 *
 * Author: Ville Nuorvala <vnuorval@tcs.hut.fi>
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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <pthread.h>

#include "debug.h"
#include "hash.h"
#include "list.h"
#include "util.h"
#include "conf.h"
#include "tunnelctl.h"
#include "rtnl.h"

#define TUNNEL_DEBUG_LEVEL 1

#if TUNNEL_DEBUG_LEVEL >= 1
#define TDBG dbg
#else
#define TDBG(x...)
#endif

const char basedev[] = "ip6tnl0";
const char basedev4[] = "sit0";
const char basedev44[] = "tunl0";

static pthread_mutex_t tnl_lock;

static int tnl_fd;
static int tnl4_fd;	/* DSMIP SIT tunnel file descriptor */
static int tnl44_fd;

struct mip6_tnl {
	struct list_head list;
	struct ip6_tnl_parm parm;	/* if sittun is set, IPv6-mapped
					   IPv4 addresses are stored here */
	struct ip_tunnel_parm parm4;	/* DSMIP SIT tunnel */
	int sittun;	/* 0 = parm is used, 1 = parm4 is used */
	int ipiptun;
	int ifindex;
	int users;
};

static inline void tnl44_parm_dump(struct ip_tunnel_parm *parm)
{
	TDBG("name: %s\n"
	     "link: %d\n"
	     "proto: %d\n"
	     "ttl: %d\n"
	     "laddr: %d.%d.%d.%d\n"
	     "raddr: %d.%d.%d.%d\n",
	     parm->name,
	     parm->link,
	     parm->iph.protocol,
	     parm->iph.ttl,
	     NIP4ADDR2(parm->iph.saddr),
	     NIP4ADDR2(parm->iph.daddr));
}

static inline void __tnl44_dump(struct mip6_tnl *tnl)
{
	tnl44_parm_dump(&tnl->parm4);
	TDBG("ifindex: %d\n"
	     "users: %d\n",
	     tnl->ifindex,
	     tnl->users);
}

static inline void tnl64_parm_dump(struct ip_tunnel_parm *parm)
{
	TDBG("name: %s\n"
	     "link: %d\n"
	     "proto: %d\n"
	     "ttl: %d\n"
	     "laddr: %d.%d.%d.%d\n"
	     "raddr: %d.%d.%d.%d\n",
	     parm->name,
	     parm->link,
	     parm->iph.protocol,
	     parm->iph.ttl,
	     NIP4ADDR2(parm->iph.saddr),
	     NIP4ADDR2(parm->iph.daddr));
}

static inline void __tnl64_dump(struct mip6_tnl *tnl)
{
	tnl64_parm_dump(&tnl->parm4);
	TDBG("ifindex: %d\n"
	     "users: %d\n",
	     tnl->ifindex,
	     tnl->users);
}

static inline void __tnl_dump(struct mip6_tnl *tnl)
{
	TDBG("name: %s\n"
	     "link: %d\n"
	     "proto: %d\n"
	     "encap_limit: %d\n"
	     "hop_limit: %d\n"
	     "flowinfo: %d\n"
	     "flags: %x\n"
	     "laddr: %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "raddr: %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "ifindex: %d\n"
	     "users: %d\n",
	     tnl->parm.name,
	     tnl->parm.link,
	     tnl->parm.proto,
	     tnl->parm.encap_limit,
	     tnl->parm.hop_limit,
	     tnl->parm.flowinfo,
	     tnl->parm.flags,
	     NIP6ADDR(&tnl->parm.laddr),
	     NIP6ADDR(&tnl->parm.raddr),
	     tnl->ifindex,
	     tnl->users);
}

static inline void tnl_dump(struct mip6_tnl *tnl)
{
	if (tnl->sittun)
		__tnl64_dump(tnl);
	else
		__tnl_dump(tnl);
}

static inline void tnl_parm_dump(struct ip6_tnl_parm *parm)
{
	TDBG("name: %s\n"
	     "link: %d\n"
	     "proto: %d\n"
	     "encap_limit: %d\n"
	     "hop_limit: %d\n"
	     "flowinfo: %d\n"
	     "flags: %x\n"
	     "laddr: %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "raddr: %x:%x:%x:%x:%x:%x:%x:%x\n"
	     "ifindex: %d\n"
	     "users: %d\n",
	     parm->name,
	     parm->link,
	     parm->proto,
	     parm->encap_limit,
	     parm->hop_limit,
	     parm->flowinfo,
	     parm->flags,
	     NIP6ADDR(&parm->laddr),
	     NIP6ADDR(&parm->raddr));
}

static inline void tnl4_dump(struct mip6_tnl *tnl)
{
	if (tnl->ipiptun)
		__tnl44_dump(tnl);
	else
		__tnl_dump(tnl);
}

#define TNL_BUCKETS 32

static struct hash tnl_hash;
static struct hash tnl4_hash; //to store 44 and 46 tunnel

LIST_HEAD(tnl_list);

static inline struct mip6_tnl *get_tnl(int ifindex)
{
	struct mip6_tnl *tnl = NULL;
	struct list_head *list;
	list_for_each(list, &tnl_list) {
		struct mip6_tnl *tmp;
		tmp = list_entry(list, struct mip6_tnl, list);
		if (tmp->ifindex == ifindex) {
			tnl = tmp;
			break;
		}
	}
	return tnl;
}

static int __tunnel44_del(struct mip6_tnl *tnl)
{
	int res = 0;

	tnl->users--;

	TDBG("tunnel %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d user count decreased to %d\n",
	     tnl->parm4.name, tnl->ifindex,
	     NIP4ADDR2(tnl->parm4.iph.saddr),
	     NIP4ADDR2(tnl->parm4.iph.daddr),
	     tnl->users);

	if (tnl->users == 0) {
		struct ifreq ifr;
		list_del(&tnl->list);
		hash_delete(&tnl4_hash, &tnl->parm.laddr, &tnl->parm.raddr);
		strcpy(ifr.ifr_name, tnl->parm4.name);
		if ((res = ioctl(tnl44_fd, SIOCDELTUNNEL, &ifr)) < 0) {
			TDBG("SIOCDELTUNNEL failed status %d %s\n",
			     errno, strerror(errno));
			res = -1;
		} else
			TDBG("tunnel deleted\n");
		free(tnl);
	}
	return res;
}

static int __tunnel64_del(struct mip6_tnl *tnl)
{
	int res = 0;

	tnl->users--;

	TDBG("tunnel %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d user count decreased to %d\n",
	     tnl->parm4.name, tnl->ifindex,
	     NIP4ADDR2(tnl->parm4.iph.saddr),
	     NIP4ADDR2(tnl->parm4.iph.daddr),
	     tnl->users);

	if (tnl->users == 0) {
		struct ifreq ifr;
		list_del(&tnl->list);
		hash_delete(&tnl_hash, &tnl->parm.laddr, &tnl->parm.raddr);
		strcpy(ifr.ifr_name, tnl->parm4.name);
		if ((res = ioctl(tnl4_fd, SIOCDELTUNNEL, &ifr)) < 0) {
			TDBG("SIOCDELTUNNEL failed status %d %s\n",
			     errno, strerror(errno));
			res = -1;
		} else
			TDBG("tunnel deleted\n");
		free(tnl);
	}
	return res;
}

static int __tunnel_del(struct mip6_tnl *tnl)
{
	int res = 0;

	tnl->users--;

	TDBG("tunnel %s (%d) from %x:%x:%x:%x:%x:%x:%x:%x "
	     "to %x:%x:%x:%x:%x:%x:%x:%x user count decreased to %d\n",
	     tnl->parm.name, tnl->ifindex,
	     NIP6ADDR(&tnl->parm.laddr), NIP6ADDR(&tnl->parm.raddr),
	     tnl->users);

	if (tnl->users == 0) {
		struct ifreq ifr;
		list_del(&tnl->list);
		hash_delete(&tnl_hash, &tnl->parm.laddr, &tnl->parm.raddr);
		strcpy(ifr.ifr_name, tnl->parm.name);
		if ((res = ioctl(tnl_fd, SIOCDELTUNNEL, &ifr)) < 0) {
			TDBG("SIOCDELTUNNEL failed status %d %s\n",
			     errno, strerror(errno));
			res = -1;
		} else
			TDBG("tunnel deleted\n");
		free(tnl);
	}
	return res;
}

/**
 * tunnel_del - delete tunnel
 * @ifindex: tunnel interface index
 *
 * Deletes a tunnel identified by @ifindex.  Returns negative if
 * tunnel does not exist, otherwise zero.
 **/
int tunnel_del(int ifindex,
	       int (*ext_tunnel_ops)(int request,
				     int old_if,
				     int new_if,
				     void *data),
	       void *data)
{
	struct mip6_tnl *tnl;
	int res = -1;

	pthread_mutex_lock(&tnl_lock);
	if ((tnl = get_tnl(ifindex)) == NULL) {
		TDBG("tunnel %d doesn't exist\n", ifindex);
		res = -1;
	} else {
		if (ext_tunnel_ops &&
		    ext_tunnel_ops(SIOCDELTUNNEL, tnl->ifindex, 0, data) < 0)
			TDBG("ext_tunnel_ops failed\n");

		if ((tnl->sittun && (res = __tunnel64_del(tnl)) < 0)
		    || (!tnl->sittun && (res = __tunnel_del(tnl)) < 0))
			TDBG("tunnel %d deletion failed\n", ifindex);
	}
	pthread_mutex_unlock(&tnl_lock);
	return res;
}

/**
 * tunnel4_del - delete tunnel
 * @ifindex: tunnel interface index
 *
 * Deletes a tunnel identified by @ifindex.  Returns negative if
 * tunnel does not exist, otherwise zero.
 **/
int tunnel4_del(int ifindex,
	       int (*ext_tunnel_ops)(int request,
				     int old_if,
				     int new_if,
				     void *data),
	       void *data)
{
	struct mip6_tnl *tnl;
	int res;

	pthread_mutex_lock(&tnl_lock);
	if ((tnl = get_tnl(ifindex)) == NULL) {
		TDBG("tunnel %d doesn't exist\n", ifindex);
		res = -1;
	} else {
		TDBG("local %x:%x:%x:%x:%x:%x:%x:%x ------ remote %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&tnl->parm.laddr), NIP6ADDR(&tnl->parm.raddr));
		if (ext_tunnel_ops &&
		    ext_tunnel_ops(SIOCDELTUNNEL, tnl->ifindex, 0, data) < 0)
			TDBG("ext_tunnel_ops failed\n");

		if (tnl->ipiptun && (res = __tunnel44_del(tnl)) < 0)
			TDBG("tunnel %d deletion failed\n", ifindex);
	}
	pthread_mutex_unlock(&tnl_lock);
	return res;
}


/**
 * __tunnel44_add - add a tunnel
 * @local: local tunnel address
 * @remote: remote tunnel address
 *
 * Create an IP4-IP4 tunnel between @local and @remote.  Returns
 * interface index of the newly created tunnel, or negative on error.
 **/
static struct mip6_tnl *__tunnel44_add(struct in6_addr *local,
				     struct in6_addr *remote,
				     int link)
{
	struct mip6_tnl *tnl = NULL;
	struct ifreq ifr;

	if ((tnl = malloc(sizeof(struct mip6_tnl))) == NULL)
		return NULL;

	memset(tnl, 0, sizeof(struct mip6_tnl));
	tnl->users = 1;

	tnl->parm4.iph.version = 4;
	tnl->parm4.iph.ihl = 5;
	tnl->parm4.iph.frag_off = htons(IP_DF);/*IP flag: Don't fragment*/
	tnl->parm4.iph.protocol = IPPROTO_IPIP;
	tnl->parm4.iph.ttl = 64;
	tnl->parm4.link = link;
	ipv6_unmap_addr(local, &tnl->parm4.iph.saddr);
	ipv6_unmap_addr(remote, &tnl->parm4.iph.daddr);
	// We also store the IPv6-mapped IPv4 addresses in the ip6_tnl_parm structure
	tnl->parm.laddr = *local;
	tnl->parm.raddr = *remote;

	strcpy(ifr.ifr_name, basedev44);
	ifr.ifr_ifru.ifru_data = (void *)&tnl->parm4;

	if (ioctl(tnl44_fd, SIOCADDTUNNEL, &ifr) < 0) {
	    TDBG("SIOCADDTUNNEL failed status %d %s\n",
		 errno, strerror(errno));
	    goto err;
	}
	strcpy(ifr.ifr_name, tnl->parm4.name);
	if (ioctl(tnl44_fd, SIOCGIFFLAGS, &ifr) < 0) {
		TDBG("SIOCGIFFLAGS failed status %d %s\n",
		     errno, strerror(errno));
		goto err;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(tnl44_fd, SIOCSIFFLAGS, &ifr) < 0) {
		TDBG("SIOCSIFFLAGS failed status %d %s\n",
		     errno, strerror(errno));
		goto err;
	}
	if (!(tnl->ifindex = if_nametoindex(tnl->parm4.name))) {
		TDBG("no device called %s\n", tnl->parm4.name);
		goto err;
	}

	if (hash_add(&tnl4_hash, tnl, &tnl->parm.laddr, &tnl->parm.raddr) < 0)
		goto err;

	list_add_tail(&tnl->list, &tnl_list);
	TDBG("created tunnel %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d user count %d\n",
	     tnl->parm4.name, tnl->ifindex,
	     NIP4ADDR2(tnl->parm4.iph.saddr),
	     NIP4ADDR2(tnl->parm4.iph.daddr),
	     tnl->users);
	tnl->ipiptun = 1;
	return tnl;
err:
	free(tnl);
	return NULL;
}

static struct mip6_tnl *__tunnel64_add(struct in6_addr *local,
				     struct in6_addr *remote,
				     int link)
{
	struct mip6_tnl *tnl = NULL;
	struct ifreq ifr;

	if ((tnl = malloc(sizeof(struct mip6_tnl))) == NULL)
		return NULL;

	memset(tnl, 0, sizeof(struct mip6_tnl));
	tnl->users = 1;

	tnl->parm4.iph.version = 4;
	tnl->parm4.iph.ihl = 5;
	tnl->parm4.iph.frag_off = htons(IP_DF);
	tnl->parm4.iph.protocol = IPPROTO_IPV6;
	tnl->parm4.iph.ttl = 64;
	//tnl->parm4.iph.tos = 0;
	tnl->parm4.link = link;
	ipv6_unmap_addr(local, &tnl->parm4.iph.saddr);
	ipv6_unmap_addr(remote, &tnl->parm4.iph.daddr);
	/* We also store the IPv6-mapped IPv4 addresses
	 * in the ip6_tnl_parm structure */
	tnl->parm.laddr = *local;
	tnl->parm.raddr = *remote;

	strcpy(ifr.ifr_name, basedev4);
	ifr.ifr_ifru.ifru_data = (void *)&tnl->parm4;

	if (ioctl(tnl4_fd, SIOCADDTUNNEL, &ifr) < 0) {
	    TDBG("SIOCADDTUNNEL failed status %d %s\n",
		 errno, strerror(errno));
	    goto err;
	}

	strcpy(ifr.ifr_name, tnl->parm4.name);
	if (ioctl(tnl4_fd, SIOCGIFFLAGS, &ifr) < 0) {
		TDBG("SIOCGIFFLAGS failed status %d %s\n",
		     errno, strerror(errno));
		goto err;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(tnl4_fd, SIOCSIFFLAGS, &ifr) < 0) {
		TDBG("SIOCSIFFLAGS failed status %d %s\n",
		     errno, strerror(errno));
		goto err;
	}

	if (!(tnl->ifindex = if_nametoindex(tnl->parm4.name))) {
		TDBG("no device called %s\n", tnl->parm4.name);
		goto err;
	}

	if (hash_add(&tnl_hash, tnl, &tnl->parm.laddr, &tnl->parm.raddr) < 0)
		goto err;

	list_add_tail(&tnl->list, &tnl_list);

	TDBG("created tunnel %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d user count %d\n",
	     tnl->parm4.name, tnl->ifindex,
	     NIP4ADDR2(tnl->parm4.iph.saddr),
	     NIP4ADDR2(tnl->parm4.iph.daddr),
	     tnl->users);
	tnl->sittun = 1;
	return tnl;
err:
	free(tnl);
	return NULL;
}

static struct mip6_tnl *__tunnel_add(struct in6_addr *local,
				     struct in6_addr *remote,
				     int link)
{
	struct mip6_tnl *tnl = NULL;
	struct ifreq ifr;

	if ((tnl = malloc(sizeof(struct mip6_tnl))) == NULL)
		return NULL;

	memset(tnl, 0, sizeof(struct mip6_tnl));
	tnl->users = 1;
	tnl->parm.proto = 0;//IPPROTO_IPIP;//IPPROTO_IPV6;
	tnl->parm.flags = IP6_TNL_F_MIP6_DEV|IP6_TNL_F_IGN_ENCAP_LIMIT;
	tnl->parm.hop_limit = 64;
	tnl->parm.laddr = *local;
	tnl->parm.raddr = *remote;
	tnl->parm.link = link;

	strcpy(ifr.ifr_name, basedev);
	ifr.ifr_ifru.ifru_data = (void *)&tnl->parm;
	if (ioctl(tnl_fd, SIOCADDTUNNEL, &ifr) < 0) {
	    TDBG("SIOCADDTUNNEL failed status %d %s\n",
		 errno, strerror(errno));
	    goto err;
	}
	if (!(tnl->parm.flags & IP6_TNL_F_MIP6_DEV)) {
		TDBG("tunnel exists,but isn't used for MIPv6\n");
		goto err;
	}
	strcpy(ifr.ifr_name, tnl->parm.name);
	if (ioctl(tnl_fd, SIOCGIFFLAGS, &ifr) < 0) {
		TDBG("SIOCGIFFLAGS failed status %d %s\n",
		     errno, strerror(errno));
		goto err;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(tnl_fd, SIOCSIFFLAGS, &ifr) < 0) {
		TDBG("SIOCSIFFLAGS failed status %d %s\n",
		     errno, strerror(errno));
		goto err;
	}
	if (!(tnl->ifindex = if_nametoindex(tnl->parm.name))) {
		TDBG("no device called %s\n", tnl->parm.name);
		goto err;
	}
	if (hash_add(&tnl_hash, tnl, &tnl->parm.laddr, &tnl->parm.raddr) < 0)
		goto err;

	list_add_tail(&tnl->list, &tnl_list);

	TDBG("created tunnel %s (%d) from %x:%x:%x:%x:%x:%x:%x:%x "
	     "to %x:%x:%x:%x:%x:%x:%x:%x user count %d\n",
	     tnl->parm.name, tnl->ifindex,
	     NIP6ADDR(&tnl->parm.laddr), NIP6ADDR(&tnl->parm.raddr),
	     tnl->users);
	tnl->sittun = 0;
	tnl->ipiptun = 0;
	return tnl;
err:
	free(tnl);
	return NULL;
}

/**
 * tunnel_add - add a tunnel
 * @local: local tunnel address
 * @remote: remote tunnel address
 *
 * Create an IP6-IP6 tunnel between @local and @remote.  Returns
 * interface index of the newly created tunnel, or negative on error.
 **/
int tunnel_add(struct in6_addr *local,
	       struct in6_addr *remote,
	       int link,
	       int (*ext_tunnel_ops)(int request,
				     int old_if,
				     int new_if,
				     void *data),
	       void *data)
{
	struct mip6_tnl *tnl;
	int res;

	if (!IN6_IS_ADDR_V4MAPPED(local))
		TDBG("Trying to add tunnel from %x:%x:%x:%x:%x:%x:%x:%x "
			 "to %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(local), NIP6ADDR(remote));
	else {
		uint32_t a4_l = 0, a4_r = 0;
		ipv6_unmap_addr(local, &a4_l);
		ipv6_unmap_addr(remote, &a4_r);
		TDBG("Trying to add tunnel from %d:%d:%d:%d "
					 "to %d:%d:%d:%d\n", NIP4ADDR((struct in_addr *)&a4_l), NIP4ADDR((struct in_addr *)&a4_r));
	}

	if(IN6_IS_ADDR_V4MAPPED(local) ^ IN6_IS_ADDR_V4MAPPED(remote)) {
		TDBG("failed: one of the local or remote address "
		     "is mapped, and not the other one.\n");
		return -1;
	}

	/* Preethi N <prenatar@cisco.com>:
	 * Support for v4-v4 handovers in DSMIP
	 * Avoid creating tunnel for a specific link number.
	 * This makes it easier to handle v4-v4 handovers
	 */
        link = 0;

	pthread_mutex_lock(&tnl_lock);
	if ((tnl = hash_get(&tnl_hash, local, remote)) != NULL) {
		tnl->users++;
		if (IN6_IS_ADDR_V4MAPPED(local)) {
			TDBG("tunnel %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d user count "
			     "increased to %d\n",
			     tnl->parm4.name, tnl->ifindex,
			     NIP4ADDR2(tnl->parm4.iph.saddr),
			     NIP4ADDR2(tnl->parm4.iph.daddr),
			     tnl->users);
		} else {
			TDBG("tunnel %s (%d) from %x:%x:%x:%x:%x:%x:%x:%x "
			     "to %x:%x:%x:%x:%x:%x:%x:%x user count increased "
			     "to %d\n",
			     tnl->parm.name, tnl->ifindex,
			     NIP6ADDR(local), NIP6ADDR(remote), tnl->users);
		}
	} else if (IN6_IS_ADDR_V4MAPPED(local)) {
		if ((tnl = __tunnel64_add(local, remote, link)) == NULL) {
			TDBG("failed to create tunnel from %d.%d.%d.%d to %d.%d.%d.%d\n",
			     NIP4ADDR2(tnl->parm4.iph.saddr),
			     NIP4ADDR2(tnl->parm4.iph.daddr));
			pthread_mutex_unlock(&tnl_lock);
			return -1;
		}
	} else {
		if ((tnl = __tunnel_add(local, remote, link)) == NULL) {
			TDBG("failed to create tunnel "
			     "from %x:%x:%x:%x:%x:%x:%x:%x "
			     "to %x:%x:%x:%x:%x:%x:%x:%x\n",
			     NIP6ADDR(local), NIP6ADDR(remote));
			pthread_mutex_unlock(&tnl_lock);
			return -1;
		}
	}
	if (ext_tunnel_ops &&
	    ext_tunnel_ops(SIOCADDTUNNEL, 0, tnl->ifindex, data) < 0) {
		TDBG("ext_tunnel_ops failed\n");
		if (IN6_IS_ADDR_V4MAPPED(local))
			__tunnel64_del(tnl);
		else
			__tunnel_del(tnl);
		pthread_mutex_unlock(&tnl_lock);
		return -1;
	}
	res = tnl->ifindex;
	pthread_mutex_unlock(&tnl_lock);
	return res;
}

/**
 * tunnel4_add - add a tunnel IP4-IP4
 * @local: local tunnel address
 * @remote: remote tunnel address
 *
 * Create an IP4-IP4 tunnel between @local and @remote.  Returns
 * interface index of the newly created tunnel, or negative on error.
 **/
int tunnel4_add(struct in6_addr *local,
	       struct in6_addr *remote,
	       int link,
	       int (*ext_tunnel_ops)(int request,
				     int old_if,
				     int new_if,
				     void *data),
	       void *data)
{
	struct mip6_tnl *tnl;
	int res;

	if(IN6_IS_ADDR_V4MAPPED(local) ^ IN6_IS_ADDR_V4MAPPED(remote)) {
		TDBG("failed: one of the local or remote address "
		     "is mapped, and not the other one.\n");
		return -1;
	}

	if (IN6_IS_ADDR_V4MAPPED(local)) {
		struct in_addr local4 = {0};
		struct in_addr remote4 = {0};
		ipv6_unmap_addr(local, &local4.s_addr);
		ipv6_unmap_addr(remote, &remote4.s_addr);
		TDBG("Trying to add tunnel v4/v4 from %d.%d.%d.%d "
			     "to %d.%d.%d.%d\n", NIP4ADDR(&local4), NIP4ADDR(&remote4));
	}else TDBG("Trying to add tunnel v4/v6 from %x:%x:%x:%x:%x:%x:%x:%x "
	     "to %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(local), NIP6ADDR(remote));

	pthread_mutex_lock(&tnl_lock);
	if ((tnl = hash_get(&tnl4_hash, local, remote)) != NULL) {
		tnl->users++;
		if (IN6_IS_ADDR_V4MAPPED(local)) {
			TDBG("tunnel %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d user count "
			     "increased to %d\n",
			     tnl->parm4.name, tnl->ifindex,
			     NIP4ADDR2(tnl->parm4.iph.saddr),
			     NIP4ADDR2(tnl->parm4.iph.daddr),
			     tnl->users);
		} else {
			TDBG("tunnel %s (%d) from %x:%x:%x:%x:%x:%x:%x:%x "
			     "to %x:%x:%x:%x:%x:%x:%x:%x user count increased "
			     "to %d\n",
			     tnl->parm.name, tnl->ifindex,
			     NIP6ADDR(local), NIP6ADDR(remote), tnl->users);
		}
	} else if (IN6_IS_ADDR_V4MAPPED(local)) {
		if ((tnl = __tunnel44_add(local, remote, link)) == NULL) {
			TDBG("failed to create tunnel from %d.%d.%d.%d to %d.%d.%d.%d\n",
			     NIP4ADDR2(tnl->parm4.iph.saddr),
			     NIP4ADDR2(tnl->parm4.iph.daddr));
			pthread_mutex_unlock(&tnl_lock);
			return -1;
		}
	}
	if (ext_tunnel_ops &&
	    ext_tunnel_ops(SIOCADDTUNNEL, 0, tnl->ifindex, data) < 0) {
		TDBG("ext_tunnel_ops failed\n");
		if (IN6_IS_ADDR_V4MAPPED(local))
			__tunnel44_del(tnl);
		pthread_mutex_unlock(&tnl_lock);
		return -1;
	}
	res = tnl->ifindex;
	TDBG("Tunnel44 created with index (%d)\n",res);
	pthread_mutex_unlock(&tnl_lock);
	return res;
}

static int __tunnel44_mod(struct mip6_tnl *tnl,
			struct in6_addr *local,
			struct in6_addr *remote,
			int link)
{
	struct ip_tunnel_parm parm;
	struct ifreq ifr;

	memset(&parm, 0, sizeof(struct ip_tunnel_parm));
	parm.iph.version = 4;
	parm.iph.ihl = 5;
	parm.iph.protocol = IPPROTO_IPIP;
	parm.iph.ttl = 64;
	ipv6_unmap_addr(local, &parm.iph.saddr);
	ipv6_unmap_addr(remote, &parm.iph.daddr);
	parm.link = link;
	parm.iph.frag_off = htons(IP_DF);

	strcpy(ifr.ifr_name, tnl->parm4.name);
	ifr.ifr_ifru.ifru_data = (void *)&parm;

	if(ioctl(tnl44_fd, SIOCCHGTUNNEL, &ifr) < 0) {
		TDBG("SIOCCHGTUNNEL failed status %d %s\n",
		     errno, strerror(errno));
		return -1;
	}
	hash_delete(&tnl4_hash, &tnl->parm.laddr, &tnl->parm.raddr);
	memcpy(&tnl->parm4, &parm, sizeof(struct ip_tunnel_parm));
	tnl->parm.laddr = *local;
	tnl->parm.raddr = *remote;
	if (hash_add(&tnl4_hash, tnl, &tnl->parm.laddr, &tnl->parm.raddr) < 0) {
		free(tnl);
		return -1;
	}
	TDBG("modified tunnel iface %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d\n",
	     tnl->parm4.name, tnl->ifindex,
	     NIP4ADDR2(parm.iph.saddr),
	     NIP4ADDR2(parm.iph.daddr));
	tnl->ipiptun = 1;
	return tnl->ifindex;
}

static int __tunnel64_mod(struct mip6_tnl *tnl,
			struct in6_addr *local,
			struct in6_addr *remote,
			int link)
{
	struct ip_tunnel_parm parm;
	struct ifreq ifr;

	memset(&parm, 0, sizeof(struct ip_tunnel_parm));
	parm.iph.version = 4;
	parm.iph.ihl = 5;
	parm.iph.protocol = IPPROTO_IPV6;
	parm.iph.ttl = 64;
	ipv6_unmap_addr(local, &parm.iph.saddr);
	ipv6_unmap_addr(remote, &parm.iph.daddr);
	parm.link = link;
	parm.iph.frag_off = htons(IP_DF);

	strcpy(ifr.ifr_name, tnl->parm4.name);
	ifr.ifr_ifru.ifru_data = (void *)&parm;

	if(ioctl(tnl4_fd, SIOCCHGTUNNEL, &ifr) < 0) {
		TDBG("SIOCCHGTUNNEL failed status %d %s\n",
		     errno, strerror(errno));
		return -1;
	}
	hash_delete(&tnl_hash, &tnl->parm.laddr, &tnl->parm.raddr);
	memcpy(&tnl->parm4, &parm, sizeof(struct ip_tunnel_parm));
	tnl->parm.laddr = *local;
	tnl->parm.raddr = *remote;
	if (hash_add(&tnl_hash, tnl, &tnl->parm.laddr, &tnl->parm.raddr) < 0) {
		free(tnl);
		return -1;
	}
	TDBG("modified tunnel iface %s (%d) from %d.%d.%d.%d to %d.%d.%d.%d\n",
	     tnl->parm4.name, tnl->ifindex,
	     NIP4ADDR2(parm.iph.saddr),
	     NIP4ADDR2(parm.iph.daddr));
	tnl->sittun = 1;
	return tnl->ifindex;
}

static int __tunnel_mod(struct mip6_tnl *tnl,
			struct in6_addr *local,
			struct in6_addr *remote,
			int link)
{
	struct ip6_tnl_parm parm;
	struct ifreq ifr;

	memset(&parm, 0, sizeof(struct ip6_tnl_parm));
	parm.proto = 0;//IPPROTO_IPIP;//IPPROTO_IPV6;
	parm.flags = IP6_TNL_F_MIP6_DEV|IP6_TNL_F_IGN_ENCAP_LIMIT;
	parm.hop_limit = 64;
	parm.laddr = *local;
	parm.raddr = *remote;
	parm.link = link;

	strcpy(ifr.ifr_name, tnl->parm.name);
	ifr.ifr_ifru.ifru_data = (void *)&parm;

	if(ioctl(tnl_fd, SIOCCHGTUNNEL, &ifr) < 0) {
		TDBG("SIOCCHGTUNNEL failed status %d %s\n",
		     errno, strerror(errno));
		return -1;
	}
	hash_delete(&tnl_hash, &tnl->parm.laddr, &tnl->parm.raddr);
	memcpy(&tnl->parm, &parm, sizeof(struct ip6_tnl_parm));
	if (hash_add(&tnl_hash, tnl, &tnl->parm.laddr, &tnl->parm.raddr) < 0) {
		free(tnl);
		return -1;
	}
	TDBG("modified tunnel iface %s (%d)"
	     "from %x:%x:%x:%x:%x:%x:%x:%x "
	     "to %x:%x:%x:%x:%x:%x:%x:%x\n",
	     tnl->parm.name, tnl->ifindex, NIP6ADDR(&tnl->parm.laddr),
	     NIP6ADDR(&tnl->parm.raddr));
	tnl->sittun = 0;
	tnl->ipiptun = 0;
	return tnl->ifindex;

}

/**
 * tunnel4_mod - modify tunnel
 * @ifindex: tunnel interface index
 * @local: new local address
 * @remote: new remote address
 *
 * Modifies tunnel end-points.  Returns negative if error, zero on
 * success.
 **/
int tunnel4_mod(int ifindex,
	       struct in6_addr *local,
	       struct in6_addr *remote,
	       int link,
	       int (*ext_tunnel_ops)(int request,
				     int old_if,
				     int new_if,
				     void *data),
	       void *data)
{
	struct mip6_tnl *old, *new;
	int res = -1;
	struct in_addr local4 = { 0 }, remote4 = { 0 };

	TDBG("Trying to mod tunnel from %x:%x:%x:%x:%x:%x:%x:%x "
	     "to %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(local), NIP6ADDR(remote));

	if(IN6_IS_ADDR_V4MAPPED(local) ^ IN6_IS_ADDR_V4MAPPED(remote)) {
		TDBG("failed: one of the local or remote address "
		     "is mapped, and not the other one.\n");
		return -1;
	}

	pthread_mutex_lock(&tnl_lock);

	old = get_tnl(ifindex);
	assert(old != NULL);

	if ((new = hash_get(&tnl4_hash, local, remote)) != NULL) {
		if (new != old) {
			new->users++;
			if (IN6_IS_ADDR_V4MAPPED(local)) {
				TDBG("tunnel %s (%d) from %d.%d.%d.%d "
				     "to %d.%d.%d.%d "
				     "user count increased to %d\n",
				     new->parm4.name, new->ifindex,
				     NIP4ADDR(&local4), NIP4ADDR(&remote4),
				     new->users);
			} else {
				TDBG("tunnel %s (%d) from "
				     "%x:%x:%x:%x:%x:%x:%x:%x to "
				     "%x:%x:%x:%x:%x:%x:%x:%x "
				     "user count increased to %d\n",
				     new->parm.name, new->ifindex,
				     NIP6ADDR(local), NIP6ADDR(remote),
				     new->users);
			}
		}
	} else {
		new = old;
		if (old->users == 1
		        && (res = __tunnel44_mod(old, local, remote, link)) < 0
		        && (new = __tunnel44_add(local, remote, link)) == NULL) {
			pthread_mutex_unlock(&tnl_lock);
			TDBG("tunnel_mod failed\n");
			return -1;
		}
	}
	if (ext_tunnel_ops &&
	    ext_tunnel_ops(SIOCCHGTUNNEL,
			   old->ifindex, new->ifindex, data) < 0) {
		TDBG("ext_tunnel_ops failed\n");
		if (old != new)
			if (new->ipiptun)
				__tunnel44_del(new);
		pthread_mutex_unlock(&tnl_lock);
		return -1;
	}
	if (old != new)
		if (old->ipiptun)
			__tunnel44_del(old);

	res = new->ifindex;
	pthread_mutex_unlock(&tnl_lock);
	return res;
}

/**
 * tunnel_mod - modify tunnel
 * @ifindex: tunnel interface index
 * @local: new local address
 * @remote: new remote address
 *
 * Modifies tunnel end-points.  Returns negative if error, zero on
 * success.
 **/
int tunnel_mod(int ifindex,
	       struct in6_addr *local,
	       struct in6_addr *remote,
	       int link,
	       int (*ext_tunnel_ops)(int request,
				     int old_if,
				     int new_if,
				     void *data),
	       void *data)
{
	struct mip6_tnl *old, *new;
	int res = -1;
	struct in_addr local4 = {INADDR_ANY}, remote4 = {INADDR_ANY};

	if (!IN6_IS_ADDR_V4MAPPED(local))
		TDBG("Trying to mod tunnel from %x:%x:%x:%x:%x:%x:%x:%x "
			 "to %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(local), NIP6ADDR(remote));
	else {
		uint32_t a4_l = 0, a4_r = 0;
		ipv6_unmap_addr(local, &a4_l);
		ipv6_unmap_addr(remote, &a4_r);
		TDBG("Trying to mod tunnel from %d:%d:%d:%d "
					 "to %d:%d:%d:%d\n", NIP4ADDR((struct in_addr *)&a4_l), NIP4ADDR((struct in_addr *)&a4_r));
	}

	if(IN6_IS_ADDR_V4MAPPED(local) ^ IN6_IS_ADDR_V4MAPPED(remote)) {
		TDBG("failed: one of the local or remote address "
		     "is mapped, and not the other one.\n");
		return -1;
	}

	pthread_mutex_lock(&tnl_lock);

	if (IN6_IS_ADDR_V4MAPPED(local)) {
		ipv6_unmap_addr(local, &local4.s_addr);
		ipv6_unmap_addr(remote, &remote4.s_addr);
		TDBG("modifying tunnel %d end points with from %d.%d.%d.%d "
		     "to %d.%d.%d.%d\n", ifindex, NIP4ADDR(&local4), NIP4ADDR(&remote4));
	} else {
		TDBG("modifying tunnel %d end points with "
		     "from %x:%x:%x:%x:%x:%x:%x:%x "
		     "to %x:%x:%x:%x:%x:%x:%x:%x\n",
		     ifindex, NIP6ADDR(local), NIP6ADDR(remote));
	}

	old = get_tnl(ifindex);
	assert(old != NULL);

	if ((new = hash_get(&tnl_hash, local, remote)) != NULL) {
		if (new != old) {
			new->users++;
			if (IN6_IS_ADDR_V4MAPPED(local)) {
				TDBG("tunnel %s (%d) from %d.%d.%d.%d "
				     "to %d.%d.%d.%d "
				     "user count increased to %d\n",
				     new->parm4.name, new->ifindex,
				     NIP4ADDR(&local4), NIP4ADDR(&remote4),
				     new->users);

			} else {
				TDBG("tunnel %s (%d) from "
				     "%x:%x:%x:%x:%x:%x:%x:%x to "
				     "%x:%x:%x:%x:%x:%x:%x:%x "
				     "user count increased to %d\n",
				     new->parm.name, new->ifindex,
				     NIP6ADDR(local), NIP6ADDR(remote),
				     new->users);
			}
		}
	} else {
		new = old;
		if (old->users == 1
		    && ((IN6_IS_ADDR_V4MAPPED(local)
		        && (res = __tunnel64_mod(old, local, remote, link)) < 0
		        && (new = __tunnel64_add(local, remote, link)) == NULL)
		        || ((!IN6_IS_ADDR_V4MAPPED(local)
			    && (res = __tunnel_mod(old, local, remote, link)) < 0
		            && (new = __tunnel_add(local, remote, link)) == NULL)))) {
			pthread_mutex_unlock(&tnl_lock);
			TDBG("tunnel_mod failed\n");
			return -1;
		}
	}
	if (ext_tunnel_ops &&
	    ext_tunnel_ops(SIOCCHGTUNNEL,
			   old->ifindex, new->ifindex, data) < 0) {
		TDBG("ext_tunnel_ops failed\n");
		if (old != new) {
			if(new->sittun)
				__tunnel64_del(new);
			else
				__tunnel_del(new);
		}
		pthread_mutex_unlock(&tnl_lock);
		return -1;
	}
	if (old != new) {
		if (old->sittun)
			__tunnel64_del(old);
		else
			__tunnel_del(old);
	}

	res = new->ifindex;
	pthread_mutex_unlock(&tnl_lock);
	return res;
}

/* DSMIPv6
 * This function could me merged with tunnel_mod
 */
int dsmip_mn_tunnel_mod(struct home_addr_info *hai,
	       struct in6_addr *local,
	       struct in6_addr *remote,
	       int link,
	       int (*ext_tunnel_ops)(int request,
				     int old_if,
				     int new_if,
				     void *data),
	       void *data)
{
	struct mip6_tnl *old, *new, *exist;
	int res = -1;
	struct in_addr local4 = {INADDR_ANY}, remote4 = {INADDR_ANY};

	if (!conf.MnUseDsmip6)
		return tunnel_mod(hai->if_tunnel, local, remote,
				  link, ext_tunnel_ops, data);

	pthread_mutex_lock(&tnl_lock);
	old = get_tnl(hai->if_tunnel);
	assert(old != NULL);

	if ((!old->sittun && !IN6_IS_ADDR_V4MAPPED(local)) ||
	    (old->sittun && IN6_IS_ADDR_V4MAPPED(local))) {
		TDBG("Old and new tunnel are of the same type\n");
		pthread_mutex_unlock(&tnl_lock);
		return tunnel_mod(hai->if_tunnel, local, remote,
				  link, ext_tunnel_ops, data);
	}
	else if (!old->sittun && IN6_IS_ADDR_V4MAPPED(local)) {
		ipv6_unmap_addr(local, &local4.s_addr);
		ipv6_unmap_addr(remote, &remote4.s_addr);
		TDBG("Old Tunnel is a v6v6 tunnel, new tunnel is v6v4\n");
		new = get_tnl(hai->if_tunnel64);
		assert(new != NULL);
		TDBG("modifying tunnel %d end points with from %d.%d.%d.%d "
		     "to %d.%d.%d.%d\n", new->ifindex, NIP4ADDR(&local4),
		     NIP4ADDR(&remote4));
		TDBG("setting v4mapped CoA on top of tunnel\n");
	}
	else {
		TDBG("Old Tunnel is a v6v4 tunnel, new tunnel is v6v6\n");
		TDBG("Removing tunnel default route in main table\n");
		if (route_del(hai->if_tunnel64, RT6_TABLE_MAIN, 1024,
					     &in6addr_any, 0,
					     &in6addr_any, 0, NULL) < 0) {
			  TDBG("dsmip route failed\n");
		}
		new = get_tnl(hai->if_tunnel66);
		assert(new != NULL);
		TDBG("modifying tunnel %d end points with "
		     "from %x:%x:%x:%x:%x:%x:%x:%x "
		     "to %x:%x:%x:%x:%x:%x:%x:%x\n",
		     new->ifindex, NIP6ADDR(local), NIP6ADDR(remote));
	}

	if ((exist = hash_get(&tnl_hash, local, remote)) != NULL) {
		if (exist != new) {
			exist->users++;
			if (IN6_IS_ADDR_V4MAPPED(local)) {
				TDBG("tunnel %s (%d) from %d.%d.%d.%d "
				     "to %d.%d.%d.%d "
				     "user count increased to %d\n",
				     exist->parm4.name, exist->ifindex,
				     NIP4ADDR(&local4), NIP4ADDR(&remote4),
				     exist->users);

			} else {
				TDBG("tunnel %s (%d) from "
				     "%x:%x:%x:%x:%x:%x:%x:%x to "
				     "%x:%x:%x:%x:%x:%x:%x:%x "
				     "user count increased to %d\n",
				     exist->parm.name, exist->ifindex,
				     NIP6ADDR(local), NIP6ADDR(remote),
				     exist->users);
			}
		}
	} else {
		if (new->users == 1
		    && ((IN6_IS_ADDR_V4MAPPED(local)
		        && (res = __tunnel64_mod(new, local, remote, link)) < 0
		        && (new = __tunnel64_add(local, remote, link)) == NULL)
		        || ((!IN6_IS_ADDR_V4MAPPED(local)
			    && (res = __tunnel_mod(new, local, remote, link)) < 0
		            && (new = __tunnel_add(local, remote, link)) == NULL)))) {
			pthread_mutex_unlock(&tnl_lock);
			return -1;
		}
	}
	if (ext_tunnel_ops &&
	    ext_tunnel_ops(SIOCCHGTUNNEL,
			   old->ifindex, new->ifindex, data) < 0) {
		TDBG("ext_tunnel_ops failed\n");
		if(!IN6_IS_ADDR_V4MAPPED(local))
			__tunnel_del(new);
		else
			__tunnel64_del(new);
		pthread_mutex_unlock(&tnl_lock);
		return -1;
	}
	if (exist != NULL && exist != new) {
		if(!IN6_IS_ADDR_V4MAPPED(local))
			__tunnel_del(new);
		else
			__tunnel64_del(new);
	}

	res = new->ifindex;
	pthread_mutex_unlock(&tnl_lock);
	return res;
}


int tunnelctl_init(void)
{
	int res = 0;
	pthread_mutexattr_t mattrs;

	if ((tnl_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		return -1;

	if ((tnl4_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	if ((tnl44_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	pthread_mutexattr_init(&mattrs);
	pthread_mutexattr_settype(&mattrs, PTHREAD_MUTEX_FAST_NP);
	if (pthread_mutex_init(&tnl_lock, &mattrs))
		return -1;

	pthread_mutex_lock(&tnl_lock);
	res = hash_init(&tnl_hash, DOUBLE_ADDR, TNL_BUCKETS);
	res += hash_init(&tnl4_hash, DOUBLE_ADDR, TNL_BUCKETS);
	pthread_mutex_unlock(&tnl_lock);
	return res;
}


static int tnl_cleanup(void *data, __attribute__ ((unused)) void *arg)
{
	struct mip6_tnl *tnl = (struct mip6_tnl *) data;
	list_del(&tnl->list);
	hash_delete(&tnl_hash, &tnl->parm.laddr, &tnl->parm.raddr);
	hash_delete(&tnl4_hash, &tnl->parm.laddr, &tnl->parm.raddr);
	free(tnl);
	return 0;
}

void tunnelctl_cleanup(void)
{
	pthread_mutex_lock(&tnl_lock);
	hash_iterate(&tnl_hash, tnl_cleanup, NULL);
	hash_cleanup(&tnl_hash);
	hash_iterate(&tnl4_hash, tnl_cleanup, NULL);
	hash_cleanup(&tnl4_hash);
	pthread_mutex_unlock(&tnl_lock);
	close(tnl_fd);
	close(tnl4_fd);
	close(tnl44_fd);
}
