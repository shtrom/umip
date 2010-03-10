/* @(#)dhcp_dna.c

 Copyright 2007 Debian User

 Author: lorchat@videonet

 Created : 13 Feb 2007

 */

#define V4_COA 5
#define V4_RTR 2

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <pthread.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/ipv6_route.h>
#include <linux/in_route.h>

#include <stdio.h>
#include <string.h>

#include "rtnl.h"
#include "movement.h"

void
dna_reachability_check(struct md_inet6_iface *iface)
{
  /* see RFC 4436 */
}

int dsmip_v4coa_add(struct ifaddrmsg *ifa, struct rtattr *rta_tb[], void *arg)
{
	struct in6_addr *addr = RTA_DATA(rta_tb[IFA_ADDRESS]);

	//	addr_del(addr, ifa->ifa_prefixlen, ifa->ifa_index);
	fprintf(stderr, "addr_add parameters : %x:%x:%x:%x:%x:%x:%x:%x, %d, %x, %d, %d, 2400000\n",
		NIP6ADDR(addr), ifa->ifa_prefixlen, ifa->ifa_flags | IFA_F_TEMPORARY | IFA_F_TENTATIVE,
		ifa->ifa_scope, ifa->ifa_index);

	return addr_add(addr, ifa->ifa_prefixlen, ifa->ifa_flags | IFA_F_TEMPORARY,
			RT_SCOPE_LINK, ifa->ifa_index, 0, 0);
}

void
dhcp_configuration(struct md_inet6_iface *iface)
{
  struct rtrequest {
    struct nlmsghdr n;
    struct rtmsg r;
    char payload[256];
  } rtreq;

  struct request {
    struct nlmsghdr msg;
    struct ifaddrmsg ifa;
    char payload[256];
  } req;

  int err = 0;
  int if_index = iface->ifindex;
  struct md_router *new;

  unsigned char local_v4_coa[4] = {192, 168, 0, V4_COA};
  unsigned char addr_v4_coa[4] = {192, 168, 0, V4_COA};
  unsigned char brd_v4_coa[4] = {192, 168, 0, 255};
  struct in_addr rtr_v4_coa;
  //  unsigned char rtr_v4_coa[4] = {192, 168, 0, V4_RTR};

  rtr_v4_coa.s_addr = htonl(0xc0a80000 | V4_RTR);

  struct in6_addr local_v4_coa_v6;

  /* later, send DHCP DISCOVER */
  /* for now, we will only statically assign an ipv4 address */

  fprintf(stderr, "dhcp_dna: dhcp configuration triggered for interface %d\n", if_index);

  memset(&req, 0, sizeof(req));

  req.msg.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.msg.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
  req.msg.nlmsg_type = RTM_NEWADDR;

  req.ifa.ifa_family = AF_INET;
  req.ifa.ifa_prefixlen = 24;
  req.ifa.ifa_flags = IFA_F_PERMANENT;
  // let scope as is : 0 = universe
  req.ifa.ifa_index = if_index;

  fprintf(stderr, "dhcp_dna: interface resolved as %s\n", iface->name);

  addattr_l(&req.msg, sizeof(req), IFA_LOCAL, &local_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_ADDRESS, &addr_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_BROADCAST, &brd_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_LABEL, iface->name, strlen(iface->name) + 1);

  if (rtnl_talk(&dna_rth, &req.msg, 0, 0, NULL, NULL, NULL) < 0)
    fprintf(stderr,"address already registered\n");
  else
    fprintf(stderr,"address modification succeeded\n");

  new = md_create_router_v4(iface, &rtr_v4_coa);

  memset(&rtreq, 0, sizeof(rtreq));

  rtreq.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  rtreq.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
  rtreq.n.nlmsg_type = RTM_NEWROUTE;

  rtreq.r.rtm_family = AF_INET;
  rtreq.r.rtm_table = RT_TABLE_MAIN;
  rtreq.r.rtm_scope = RT_SCOPE_UNIVERSE;
  rtreq.r.rtm_type = RTN_UNICAST;

  addattr_l(&rtreq.n, sizeof(rtreq), RTA_GATEWAY, &rtr_v4_coa.s_addr, 4);
  addattr32(&rtreq.n, sizeof(rtreq), RTA_OIF, if_index);

  if (rtnl_talk(&dna_rth, &rtreq.n, 0, 0, NULL, NULL, NULL) < 0)
    fprintf(stderr,"route already setup\n");
  else {
    fprintf(stderr,"route modification succeeded\n");
    list_add(&new->list, &iface->v4_rtrs);
  }

  memset(&local_v4_coa_v6, 0, sizeof(struct in6_addr));
  local_v4_coa_v6.s6_addr32[2] = htonl (0xffff);
  memcpy(&local_v4_coa_v6.s6_addr32[3], local_v4_coa, 4);

  fprintf(stderr,"adding address %x:%x:%x:%x:%x:%x:%x:%x on interface %d\n", NIP6ADDR(&local_v4_coa_v6), if_index);
  if ((err = addr_do(&local_v4_coa_v6, 128, if_index, NULL, dsmip_v4coa_add)) < 0) {
    fprintf(stderr,"warning : unable to set v4mapped address on interface, error %d", err);
  }

}

void
dhcp_link_down(struct md_inet6_iface *iface)
{
  struct request {
    struct nlmsghdr msg;
    struct ifaddrmsg ifa;
    char payload[256];
  } req;

  int err = 0;
  int if_index = iface->ifindex;

  unsigned char local_v4_coa[4] = {192, 168, 0, V4_COA};
  unsigned char addr_v4_coa[4] = {192, 168, 0, V4_COA};
  unsigned char brd_v4_coa[4] = {192, 168, 0, 255};

  struct in6_addr local_v4_coa_v6;

  /* later, handle DHCP protocol */
  /* for now, we will only statically remove ipv4 address */

  fprintf(stderr, "dhcp_dna: dhcp de-configuration triggered for interface %s(%d)\n", iface->name, if_index);

  memset(&req, 0, sizeof(req));

  req.msg.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.msg.nlmsg_flags = NLM_F_REQUEST;
  req.msg.nlmsg_type = RTM_DELADDR;

  req.ifa.ifa_family = AF_INET;
  req.ifa.ifa_prefixlen = 24;
  req.ifa.ifa_flags = IFA_F_PERMANENT;
  req.ifa.ifa_index = if_index;

  addattr_l(&req.msg, sizeof(req), IFA_LOCAL, &local_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_ADDRESS, &addr_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_BROADCAST, &brd_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_LABEL, iface->name, strlen(iface->name) + 1);

  if (rtnl_talk(&dna_rth, &req.msg, 0, 0, NULL, NULL, NULL) < 0)
	fprintf(stderr, "address could not be removed\n");
  else
	fprintf(stderr, "address removed\n");

  memset(&local_v4_coa_v6, 0, sizeof(struct in6_addr));
  local_v4_coa_v6.s6_addr32[2] = htonl (0xffff);
  memcpy(&local_v4_coa_v6.s6_addr32[3], local_v4_coa, 4);

  fprintf(stderr,"removing address %x:%x:%x:%x:%x:%x:%x:%x on interface %d\n", NIP6ADDR(&local_v4_coa_v6), if_index);
  if ((err = addr_del(&local_v4_coa_v6, 128, if_index)) < 0) {
    fprintf(stderr,"warning : unable to remove v4mapped address on interface, error %d", err);
  }
}
