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

void
dna_reachability_check(struct md_inet6_iface *);

void
dhcp_configuration(struct md_inet6_iface *);

void
dhcp_link_down(struct md_inet6_iface *);

#endif /* __DHCP_DNA_H__ */

