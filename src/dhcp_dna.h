/* @(#)dhcp_dna.h

 Copyright 2007 Debian User

 Author: lorchat@videonet

 Created : 14 Feb 2007

 */

#ifndef __DHCP_DNA_H__
#define __DHCP_DNA_H__

#include "movement.h"

#define DHCP_RUNNING	1
#define DHCP_ACQUIRED	2

int
dhcp_dna_init(void);

void
dna_reachability_check(struct md_inet6_iface *);

void
trigger_dhcp_configuration(struct md_inet6_iface *);

int
dhcp_configuration(struct md_inet6_iface *);

void
dhcp_link_down(struct md_inet6_iface *);

/* Preethi N <prenatar@cisco.com>
 * Support external DCHP client in DSMIP
 * dsmip_v4coa_add must be visible to movement.c 
 */
struct ifaddrmsg;
struct rtattr;
int 
dsmip_v4coa_add(struct ifaddrmsg *, struct rtattr *[], void *);

/* udhcp imported, rfc related defines */

#define DHCP_INIT_SELECTING	0
#define DHCP_REQUESTING		1
#define DHCP_BOUND		2
#define DHCP_RENEWING		3
#define DHCP_REBINDING		4
#define DHCP_INIT_REBOOT	5
#define DHCP_RENEW_REQUESTED	6
#define DHCP_RELEASED		7
#define DHCP_POLL		8

#define DHCP_SERVER_PORT	67
#define DHCP_CLIENT_PORT	68

#define DHCP_MAGIC		0x63825363

/* DHCP option codes (partial list) */
#define DHCP_PADDING		0x00
#define DHCP_SUBNET		0x01
#define DHCP_TIME_OFFSET	0x02
#define DHCP_ROUTER		0x03
#define DHCP_TIME_SERVER	0x04
#define DHCP_NAME_SERVER	0x05
#define DHCP_DNS_SERVER		0x06
#define DHCP_LOG_SERVER		0x07
#define DHCP_COOKIE_SERVER	0x08
#define DHCP_LPR_SERVER		0x09
#define DHCP_HOST_NAME		0x0c
#define DHCP_BOOT_SIZE		0x0d
#define DHCP_DOMAIN_NAME	0x0f
#define DHCP_SWAP_SERVER	0x10
#define DHCP_ROOT_PATH		0x11
#define DHCP_IP_TTL		0x17
#define DHCP_MTU		0x1a
#define DHCP_BROADCAST		0x1c
#define DHCP_NTP_SERVER		0x2a
#define DHCP_WINS_SERVER	0x2c
#define DHCP_REQUESTED_IP	0x32
#define DHCP_LEASE_TIME		0x33
#define DHCP_OPTION_OVER	0x34
#define DHCP_MESSAGE_TYPE	0x35
#define DHCP_SERVER_ID		0x36
#define DHCP_PARAM_REQ		0x37
#define DHCP_MESSAGE		0x38
#define DHCP_MAX_SIZE		0x39
#define DHCP_T1			0x3a
#define DHCP_T2			0x3b
#define DHCP_VENDOR		0x3c
#define DHCP_CLIENT_ID		0x3d

#define DHCP_END		0xFF


#define DHCP_BOOTREQUEST	1
#define DHCP_BOOTREPLY		2

#define DHCP_ETH_10MB		1
#define DHCP_ETH_10MB_LEN	6

#define DHCPDISCOVER		1
#define DHCPOFFER		2
#define DHCPREQUEST		3
#define DHCPDECLINE		4
#define DHCPACK			5
#define DHCPNAK			6
#define DHCPRELEASE		7
#define DHCPINFORM		8

#define DHCP_BROADCAST_FLAG	0x8000

#define DHCP_OPTION_FIELD	0
#define DHCP_FILE_FIELD		1
#define DHCP_SNAME_FIELD	2

/* miscellaneous defines */
#define DHCP_MAC_BCAST_ADDR	(unsigned char *) "\xff\xff\xff\xff\xff\xff"
#define DHCP_OPT_CODE		0
#define DHCP_OPT_LEN		1
#define DHCP_OPT_DATA		2
#define DHCP_OPTION_REQ		0x10
#define DHCP_OPTION_LIST	0x20
#define DHCP_OPTION_FIELD       0
#define DHCP_FILE_FIELD         1
#define DHCP_SNAME_FIELD        2
#define DHCP_TYPE_MASK		0x0F

struct dhcp_option {
        char name[10];
        char flags;
        unsigned char code;
};

struct option_set {
        unsigned char *data;
        struct option_set *next;
};

struct dhcp_dna_control_s {
  /* listening socket related stuff */
#define DHCP_DNA_LISTEN_MODE_NONE	0
#define DHCP_DNA_LISTEN_MODE_KERNEL	1
#define DHCP_DNA_LISTEN_MODE_RAW	2
  char mode;
  int in_fd;
  int if_index;
  /* DHCP state machine and protocol related global stuff */
  int state;
  int seq_num;
  unsigned long timeout;
  unsigned long server;
  unsigned long requested_ip;
  unsigned long netmask;
  unsigned long gateway;
  /* client config imported data */
  unsigned char arp[6];
  unsigned char *clientid;
  unsigned long t1, t2, lease;
  unsigned long xid;
  unsigned long start;
};

#endif /* __DHCP_DNA_H__ */

