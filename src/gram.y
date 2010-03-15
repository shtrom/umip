/*
 * $Id: gram.y 1.88 06/05/12 11:48:36+03:00 vnuorval@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 *
 * Authors: Antti Tuominen <anttit@tcs.hut.fi>
 *          Ville Nuorvala <vnuorval@tcs.hut.fi>
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
 * 02111-1307 USA
 */

%{

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/ip6mh.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "mipv6.h"
#include "ha.h"
#include "mn.h"
#include "cn.h"
#include "conf.h"
#include "policy.h"
#include "xfrm.h"
#include "prefix.h"
#include "hoa4.h"
#include "util.h"
#include "ipsec.h"
#include "rtnl.h"
#include "bul.h"

struct net_iface ni = {
	.mip6_if_entity = MIP6_ENTITY_NO,
	.mn_if_preference = POL_MN_IF_DEF_PREFERENCE,
	.is_tunnel = 0,
};

struct home_addr_info hai = {
	.ro_policies = LIST_HEAD_INIT(hai.ro_policies),
	.mob_net_prefixes = LIST_HEAD_INIT(hai.mob_net_prefixes),
	.mnp4_count = 0,
};

LIST_HEAD(prefixes);

int mv_prefixes(struct list_head *list)
{
	struct list_head *l, *n;
	int res = 0;
	list_for_each_safe(l, n, &prefixes) {
		list_del(l);
		list_add_tail(l, list);
		res++;
	}
	return res;
}

struct hoa4_mnp4 *hoa41_Nmnp4 = NULL;

struct net_prefix4 *HAmnp4 = NULL;

struct policy_bind_acl_entry *bae = NULL;
struct cn_binding_pol_entry *cnbpol = NULL;

struct ipsec_policy_set {
	struct in6_addr ha;
	struct in_addr ha4;
	struct list_head hoa_list;
};

struct ipsec_policy_set ipsec_ps = {
	.hoa_list = LIST_HEAD_INIT(ipsec_ps.hoa_list)
};

extern int lineno;
extern char *yytext;

static void yyerror(char *s) {
	fprintf(stderr, "Error in configuration file %s\n", conf_parsed->config_file);
	fprintf(stderr, "line %d: %s at '%s'\n", lineno, s, yytext);
}

static void uerror(const char *fmt, ...) {
	char s[1024];
	va_list args;

	fprintf(stderr, "Error in configuration file %s\n", conf_parsed->config_file);
	va_start(args, fmt);
	vsprintf(s, fmt, args);
	fprintf(stderr, "line %d: %s\n", lineno, s);
	va_end(args);
}

%}

%union {
	char *string;
	struct in6_addr addr;
	struct in_addr addr4;
	char bool;
	unsigned int num;
	unsigned int numpair[2];
	double dec;
}

%token <string> QSTRING
%token <addr>	ADDR
%token <addr4>	ADDR4
%token <bool>	BOOL
%token <num>	NUMBER
%token <dec>	DECIMAL
%token <numpair>	NUMPAIR;

%token		MIP6ENTITY
%token		DEBUGLEVEL
%token		DEBUGLOGFILE
%token		DOROUTEOPTIMIZATIONCN
%token		DOROUTEOPTIMIZATIONMN
%token		HOMEADDRESS
%token      HOMEADDRESS4
%token		HOMEAGENTADDRESS
%token		HOMEAGENTADDRESS4
%token		HOMEAGENTNAME
%token		INITIALBINDACKTIMEOUTFIRSTREG
%token		INITIALBINDACKTIMEOUTREREG
%token		INITIALSOLICITTIMER
%token		LINKNAME
%token		HAMAXBINDINGLIFE
%token		MNMAXHABINDINGLIFE
%token		MNMAXCNBINDINGLIFE
%token		MAXMOBPFXADVINTERVAL
%token		MINMOBPFXADVINTERVAL
%token		MNHOMELINK
%token		HAHOMELINK
%token		NONVOLATILEBINDINGCACHE
%token		SENDMOBPFXSOLS
%token		SENDUNSOLMOBPFXADVS
%token		SENDMOBPFXADVS
%token		IPSECPOLICYSET
%token		IPSECPOLICY
%token		IPSECTYPE
%token		USEALTCOA
%token		USEESP
%token		USEAH
%token		USEIPCOMP
%token		BLOCK
%token		USEMNHAIPSEC
%token		KEYMNGMOBCAPABILITY
%token		TUNNELPAYLOADFORCESANEGO
%token		HOMEREGBINDING
%token		MH
%token		MOBPFXDISC
%token		TUNNELHOMETESTING
%token		TUNNELMH
%token		TUNNELPAYLOAD
%token		USEMOVEMENTMODULE
%token		USEPOLICYMODULE
%token		MIP6CN
%token		MIP6MN
%token		MIP6HA
%token		INTERNAL
%token		MNROPOLICY
%token		ICMP
%token		ANY
%token		DOROUTEOPT
%token		DEFAULTBINDINGACLPOLICY
%token		BINDINGACLPOLICY
%token		MNADDRESS
%token		USECNBUACK
%token		INTERFACE
%token		IFNAME
%token		IFTYPE
%token		MNIFPREFERENCE
%token		ISTUNNEL
%token		MNUSEALLINTERFACES
%token		MNROUTERPROBES
%token		MNROUTERPROBETIMEOUT
%token		MNDISCARDHAPARAMPROB
%token		OPTIMISTICHANDOFF
%token		HOMEPREFIX
%token		HOMEPREFIX4
%token		HAACCEPTMOBRTR
%token		ISMOBRTR
%token		HASERVEDPREFIX
%token		MOBRTRUSEEXPLICITMODE
%token          CNBINDINGPOLICYSET
%token		MNUSEDSMIP6
%token		MNSUPPORTIPV4TRAFFIC
%token		HAACCEPTDSMIP6
%token		MNP4
%token		IFUSEDHCP

%token		INV_TOKEN

%type <num>	ipsectype
%type <num>	ipsectypeval
%type <num>	ipsecproto
%type <num>	ipsecprotos
%type <numpair>	ipsecreqid

%type <addr>	mnropolicyaddr
%type <bool>	dorouteopt
%type <num>		bindaclpolval
%type <num>		prefixlen
%type <num>		prefixlen4
%type <num>		mip6entity
%type <bool>	xfrmaction

%%

grammar		: topdef
		| grammar topdef
		;

topdef		: MIP6ENTITY mip6entity ';'
		{
			conf_parsed->mip6_entity = $2;
		}
		| DEBUGLEVEL NUMBER ';'
		{
			conf_parsed->debug_level = $2;
		}
		| DEBUGLOGFILE QSTRING ';'
		{
			conf_parsed->debug_log_file = $2;
		}
		| NONVOLATILEBINDINGCACHE BOOL ';'
		{
			conf_parsed->NonVolatileBindingCache = $2;
		}
		| INTERFACE ifacedef
		| SENDMOBPFXSOLS BOOL ';'
		{
			conf_parsed->SendMobPfxSols = $2;
		}
		| SENDUNSOLMOBPFXADVS BOOL ';'
		{
			conf_parsed->SendUnsolMobPfxAdvs = $2;
		}
		| SENDMOBPFXADVS BOOL ';'
		{
			conf_parsed->SendMobPfxAdvs = $2;
		}
		| MAXMOBPFXADVINTERVAL NUMBER ';'
		{
			conf_parsed->MaxMobPfxAdvInterval = $2;
		}
		| MINMOBPFXADVINTERVAL NUMBER ';'
		{
			conf_parsed->MinMobPfxAdvInterval = $2;
		}
		| DOROUTEOPTIMIZATIONCN BOOL ';'
		{
			conf_parsed->DoRouteOptimizationCN = $2;
		}
		| DOROUTEOPTIMIZATIONMN BOOL ';'
		{
			conf_parsed->DoRouteOptimizationMN = $2;
		}
		| HAMAXBINDINGLIFE NUMBER ';'
		{
			if ($2 > MAX_BINDING_LIFETIME) {
				uerror("max allowed binding lifetime is %d",
				       MAX_BINDING_LIFETIME);
				return -1;
			}
			conf_parsed->HaMaxBindingLife = $2;
		}
		| MNMAXHABINDINGLIFE NUMBER ';'
		{
			if ($2 > MAX_BINDING_LIFETIME) {
				uerror("max allowed binding lifetime is %d",
				       MAX_BINDING_LIFETIME);
				return -1;
			}
			conf_parsed->MnMaxHaBindingLife = $2;
		}
		| MNMAXCNBINDINGLIFE NUMBER ';'
		{
			if ($2 > MAX_RR_BINDING_LIFETIME) {
				uerror("max allowed binding lifetime is %d",
				       MAX_RR_BINDING_LIFETIME);
				return -1;
			}
			conf_parsed->MnMaxCnBindingLife = $2;
		}
		| INITIALBINDACKTIMEOUTFIRSTREG DECIMAL ';'
		{
			tssetdsec(conf_parsed->InitialBindackTimeoutFirstReg_ts, $2);
		}
		| INITIALBINDACKTIMEOUTREREG DECIMAL ';'
		{
			tssetdsec(conf_parsed->InitialBindackTimeoutReReg_ts, $2);
		}
		| INITIALSOLICITTIMER DECIMAL ';'
		{
			tssetdsec(conf_parsed->InitialSolicitTimer_ts, $2);
		}
		| MNHOMELINK linksub
		| USEMNHAIPSEC BOOL ';'
		{
			conf_parsed->UseMnHaIPsec = $2;
		}
		| KEYMNGMOBCAPABILITY BOOL  ';'
		{
			conf_parsed->KeyMngMobCapability = $2;
		}
		| TUNNELPAYLOADFORCESANEGO BOOL  ';'
		{
			conf_parsed->TunnelPayloadForceSANego = $2;
		}
		| USEMOVEMENTMODULE movemodule ';'
		| USEPOLICYMODULE policymodule ';'
		| DEFAULTBINDINGACLPOLICY bindaclpolval ';'
		{
			conf_parsed->DefaultBindingAclPolicy = $2;
		}
		| HAACCEPTMOBRTR BOOL ';'
		{
			conf_parsed->HaAcceptMobRtr = $2;
		}
		| HASERVEDPREFIX prefixlistentry ';'
		{
			list_splice(&prefixes,
				    conf_parsed->nemo_ha_served_prefixes.prev);
		}
		| MOBRTRUSEEXPLICITMODE BOOL ';'
		{
			conf_parsed->MobRtrUseExplicitMode = $2;
		}
		| BINDINGACLPOLICY bindaclpolicy ';'
		{
			bae = NULL;
		}
		| USECNBUACK BOOL ';'
		{
			conf_parsed->CnBuAck = $2 ? IP6_MH_BU_ACK : 0;
		}
		| IPSECPOLICYSET '{' ipsecpolicyset '}'
		| MNUSEALLINTERFACES BOOL ';'
		{
			conf_parsed->MnUseAllInterfaces = $2 ? POL_MN_IF_DEF_PREFERENCE : 0;
		}
		| MNROUTERPROBES NUMBER ';'
		{
			conf_parsed->MnRouterProbes = $2;
		}
		| MNROUTERPROBETIMEOUT DECIMAL ';'
		{
			if ($2 > 0)
				tssetdsec(conf_parsed->MnRouterProbeTimeout_ts, $2);
		}
		| MNDISCARDHAPARAMPROB BOOL ';'
		{
			conf_parsed->MnDiscardHaParamProb = $2;
		}
		| OPTIMISTICHANDOFF BOOL ';'
		{
			conf_parsed->OptimisticHandoff = $2;
		}
                | CNBINDINGPOLICYSET  '{' cnbindingpoldefs '}'
		;

mip6entity	: MIP6CN { $$ = MIP6_ENTITY_CN;	}
		| MIP6MN { $$ = MIP6_ENTITY_MN; }
		| MIP6HA { $$ = MIP6_ENTITY_HA; }
		;

ifacedef	: QSTRING ifacesub
		{
			struct net_iface *nni;
			strncpy(ni.name, $1, IF_NAMESIZE - 1);
			ni.ifindex = if_nametoindex($1);

			if (is_if_ha(&ni) && ni.is_tunnel) {
				/* We do not allow tunnel interfaces
				   for HA, only for MN and CN */
				uerror("Use of tunnel interface is not possible for HA yet");
				free($1);
					return -1;
			}
			if (ni.ifindex <= 0) {
				if (is_if_ha(&ni)) {
					/* We do not allow unavailable ifaces for HA ... */
					uerror("HA interface %s unavailable", $1);
					free($1);
					return -1;
				}
				/* ... but allow them for CN and MN */
				free($1);
			}
			nni = malloc(sizeof(struct net_iface));
			if (nni == NULL) {
				uerror("out of memory");
				return -1;
			}
			memcpy(nni, &ni, sizeof(struct net_iface));
			list_add_tail(&nni->list, &conf_parsed->net_ifaces);
			if (is_if_ha(nni))
				homeagent_if_init(nni->ifindex);

			memset(&ni, 0, sizeof(struct net_iface));
			ni.mip6_if_entity = MIP6_ENTITY_NO;
			ni.mn_if_preference = POL_MN_IF_DEF_PREFERENCE;
		}
		| MNUSEDSMIP6 BOOL ';'
		{
			conf.MnUseDsmip6 = $2;
		}
		| HAACCEPTDSMIP6 BOOL ';'
		{
			conf.HaAcceptDsmip6 = $2;
		}
		| HOMEAGENTADDRESS4 ADDR4 ';'
		{
			ipv6_map_addr(&conf.HaAddr4Mapped, &$2);
		}
		| IFUSEDHCP BOOL ';'
		{
                        /* Preethi N, 03/2010. Support external DCHP client in DSMIP
                         * Testing if UseDhcp is en(dis)abled
                         */
                        if ($2) {

				ni.dhcp_ctrl = malloc(sizeof(struct dhcp_dna_control_s));
				if (ni.dhcp_ctrl == NULL) {
					uerror("out of memory");
					return -1;
				}
				memset(ni.dhcp_ctrl, 0, sizeof(*ni.dhcp_ctrl));
			} else {
				ni.dhcp_ctrl = NULL;
			}
		}
		| MNSUPPORTIPV4TRAFFIC BOOL ';'
		{
			conf.MnSupportIPv4Traffic = $2;
		}
		| MNP4 ADDR4 HAprefixlistsub4 ';'
		{
			hoa41_Nmnp4 = malloc(sizeof(struct hoa4_mnp4));
			if (hoa41_Nmnp4 == NULL) {
				uerror("out of memory");
				return -1;
			}
			hoa41_Nmnp4->hoa4 = $2;
			hoa41_Nmnp4->mob_net_prefixes4 = HAmnp4;
			hoa41_Nmnp4->next = NULL;
			hoa41_Nmnp4->hoa4_enabled_by_MR = 0;
			hoa41_Nmnp4->mnp4_count = 0;
			
			struct net_prefix4 *current4 = hoa41_Nmnp4->mob_net_prefixes4;
			while (current4 != NULL) {
				current4 = current4->next;
				hoa41_Nmnp4->mnp4_count ++;
			} 
		
			struct hoa4_mnp4 *current = conf.mnpv4;
			if (conf.mnpv4 != NULL) {
				while (current->next != NULL) current = current->next;
				current->next = hoa41_Nmnp4;
			} 
			else conf.mnpv4 = hoa41_Nmnp4;
			HAmnp4 = NULL;
		}	
		;

ifacesub	: '{' ifaceopts '}'
		| ';'
		;

ifaceopts	: ifaceopt
		| ifaceopts ifaceopt
		;

ifaceopt	: IFTYPE mip6entity ';'
		{
			ni.mip6_if_entity = $2;
		}
		| MNIFPREFERENCE NUMBER ';'
		{
			int pref = $2;
			if ((pref > POL_MN_IF_MIN_PREFERENCE) || (pref < 0)) {
				uerror("Found bad interface preference value (%d). Valid range is [0,%d].\n",
				       pref,
				       POL_MN_IF_MIN_PREFERENCE);
				return -1;
			}
 			ni.mn_if_preference = pref;
		}
		| ISTUNNEL BOOL ';'
		{
			ni.is_tunnel = $2;
		}
		;

linksub		: QSTRING '{' linkdefs '}'
		{
			struct home_addr_info *nhai;
			if (IN6_IS_ADDR_UNSPECIFIED(&hai.hoa.addr)) {
				uerror("No home addresses defined"
					"for homelink %d", hai.if_home);
				return -1;
			}
			strncpy(hai.name, $1, IF_NAMESIZE - 1);
			hai.if_home = if_nametoindex($1);
			free($1);
			if (hai.if_home <= 0) {
				uerror("invalid interface");
				return -1;
			}
			nhai = malloc(sizeof(struct home_addr_info));
			if (nhai == NULL) {
				uerror("out of memory");
				return -1;
			}
			if (hai.plen == 64) {
				struct in6_addr lladdr;
				ipv6_addr_llocal(&hai.hoa.addr, &lladdr);
				if (!addr_do(&lladdr, 64,
					     hai.if_home, NULL, NULL))
					hai.lladdr_comp = IP6_MH_BU_LLOCAL;
			}
			if (IN6_IS_ADDR_UNSPECIFIED(&hai.home_prefix)) {
				ipv6_addr_prefix(&hai.home_prefix,
						 &hai.hoa.addr, hai.plen);
				hai.home_plen = hai.plen;
			}
			memcpy(nhai, &hai, sizeof(struct home_addr_info));
			INIT_LIST_HEAD(&nhai->ro_policies);
			INIT_LIST_HEAD(&nhai->ha_list.home_agents);
			INIT_LIST_HEAD(&nhai->mob_net_prefixes);
			nhai->ha_list.dhaad_id = -1;
			list_splice(&hai.ro_policies, &nhai->ro_policies);
			list_splice(&hai.mob_net_prefixes,
				    &nhai->mob_net_prefixes);
			list_add_tail(&nhai->list, &conf_parsed->home_addrs);

			memset(&hai, 0, sizeof(struct home_addr_info));
			INIT_LIST_HEAD(&hai.ro_policies);
			INIT_LIST_HEAD(&hai.mob_net_prefixes);
		}
		;

linkdefs	: linkdef
		| linkdefs linkdef
		;

linkdef		: HOMEAGENTADDRESS ADDR ';'
		{
			/* If both HomeAgentAddress and HomeAgentName are specified, the Name is ignored */
			memcpy(&hai.ha_addr, &$2, sizeof(struct in6_addr));
		}
		| HOMEAGENTADDRESS4 ADDR4 ';'
		{
			/* If both HomeAgentV4Address and HomeAgentName are specified, the Name is ignored */
			memcpy(&hai.ha_addr4, &$2, sizeof(struct in_addr));
		}
		| HOMEAGENTNAME QSTRING ';'
		{
			struct addrinfo *res=NULL, *ad=NULL;
			int ret=0;
			struct sockaddr_in6 * sin6;
			struct sockaddr_in  * sin4;

			ret = getaddrinfo($2, NULL, NULL, &res);
			if (ret != 0) {
				uerror("Error resolving %s: %s", $2, gai_strerror(ret));
				return -1;
			}

			for (ad=res; ad != NULL; ad = ad->ai_next) {
				switch (ad->ai_family) {
					case PF_INET6:
						if (IN6_IS_ADDR_UNSPECIFIED(&hai.ha_addr)) {
							if (ad->ai_addrlen != sizeof(struct sockaddr_in6)) {
								uerror("Internal error in getaddrinfo");
								return -1;
							}
							sin6 = (struct sockaddr_in6 *)ad->ai_addr;
							memcpy(&hai.ha_addr, &sin6->sin6_addr, sizeof(struct in6_addr));
						}
						break;

					case PF_INET:
						if (IN4_IS_ADDR_UNSPECIFIED(&hai.ha_addr4)) {
							if (ad->ai_addrlen != sizeof(struct sockaddr_in)) {
								uerror("Internal error in getaddrinfo");
								return -1;
							}
							sin4 = (struct sockaddr_in *)ad->ai_addr;
							memcpy(&hai.ha_addr4, &sin4->sin_addr, sizeof(struct in_addr));
						}
						break;

				}
			}

			freeaddrinfo(res);
		}
		| HOMEADDRESS homeaddress ';'
		| HOMEADDRESS4 homeaddress4 ';'
		| USEALTCOA BOOL ';'
                {
		        hai.altcoa = $2;
		}
		| MNROPOLICY mnropolicy ';'
		| ISMOBRTR BOOL ';'
                {
			if ($2)
				hai.mob_rtr = IP6_MH_BU_MR;
		}
		|  HOMEPREFIX ADDR '/' prefixlen ';'
        {
			ipv6_addr_prefix(&hai.home_prefix, &$2, $4);
			hai.home_plen = $4;
		}
		|  HOMEPREFIX4 ADDR4 '/' prefixlen4 ';'
        {
			ipv4_addr_prefix(&hai.home_prefix4, &$2, $4);
			hai.home_plen4 = $4;
		}
		;

homeaddress	: homeaddrdef prefixlistsub
		{
			hai.mnp_count = mv_prefixes(&hai.mob_net_prefixes);
		}
		;

homeaddrdef	: ADDR '/' prefixlen
		{
			hai.hoa.addr = $1;
			hai.plen = $3;
		}
		;

homeaddress4    : homeaddrdef4 prefixlistsub4
        {
        }
        ;

homeaddrdef4    : ADDR4 '/' prefixlen4
       	{
			hai.hoa.addr4 = $1;
			hai.plen4 = $3;
		}
		;

ipsecpolicyset	: ipsechaaddrdef ipsecmnaddrdefs ipsecpolicydefs
		{
			if (!list_empty(&ipsec_ps.hoa_list)) {
				struct list_head *lp, *tmp;

				/* free each hoa entry */
				list_for_each_safe(lp, tmp,
						   &ipsec_ps.hoa_list) {
					struct home_addr_info *hoa;

					list_del(lp);
					hoa = list_entry(lp,
							 struct home_addr_info,
							 list);

					free(hoa);
				}
			}
			memset(&ipsec_ps, 0, sizeof(ipsec_ps));
			INIT_LIST_HEAD(&ipsec_ps.hoa_list);
		}
		;

ipsechaaddrdef	: HOMEAGENTADDRESS ADDR ';'
		{
			ipsec_ps.ha = $2;
		}
		| HOMEAGENTADDRESS4 ADDR4 ';'
		{
			ipsec_ps.ha4 = $2;
		}
		| HOMEAGENTNAME QSTRING ';'
		{
			struct addrinfo *res=NULL, *ad=NULL;
			int ret=0;
			struct sockaddr_in6 * sin6;
			struct sockaddr_in  * sin4;

			ret = getaddrinfo($2, NULL, NULL, &res);
			if (ret != 0) {
				uerror("Error resolving %s: %s", $2, gai_strerror(ret));
				return -1;
			}

			for (ad=res; ad != NULL; ad = ad->ai_next) {
				switch (ad->ai_family) {
					case PF_INET6:
						if (IN6_IS_ADDR_UNSPECIFIED(&ipsec_ps.ha)) {
							if (ad->ai_addrlen != sizeof(struct sockaddr_in6)) {
								uerror("Internal error in getaddrinfo");
								return -1;
							}
							sin6 = (struct sockaddr_in6 *)ad->ai_addr;
							memcpy(&ipsec_ps.ha, &sin6->sin6_addr, sizeof(struct in6_addr));
						}
						break;

					case PF_INET:
						if (IN4_IS_ADDR_UNSPECIFIED(&ipsec_ps.ha4)) {
							if (ad->ai_addrlen != sizeof(struct sockaddr_in)) {
								uerror("Internal error in getaddrinfo");
								return -1;
							}
							sin4 = (struct sockaddr_in *)ad->ai_addr;
							memcpy(&ipsec_ps.ha4, &sin4->sin_addr, sizeof(struct in_addr));
						}
						break;

				}
			}

			freeaddrinfo(res);
		}
		;

ipsecmnaddrdefs	: ipsecmnaddrdef
		| ipsecmnaddrdefs ipsecmnaddrdef
		;

ipsecmnaddrdef	: HOMEADDRESS ipsecmnaddr ';'
		;

ipsecmnaddr	: ADDR '/' prefixlen
		{
			struct home_addr_info *hai;

			hai = malloc(sizeof(struct home_addr_info));
			if (hai == NULL) {
				uerror("out of memory");
				return -1;
			}
			memset(hai, 0, sizeof(struct home_addr_info));
			hai->hoa.addr = $1;
			hai->plen = $3;
			list_add_tail(&hai->list, &ipsec_ps.hoa_list);
		}
		;

ipsecpolicydefs	: ipsecpolicydef
		| ipsecpolicydefs ipsecpolicydef
		;

ipsecpolicydef	: ipsectype ipsecprotos ipsecreqid xfrmaction ';'
		{
			struct list_head *lp;

			if (IN6_IS_ADDR_UNSPECIFIED(&ipsec_ps.ha)) {
				uerror("HomeAgentAddress missing for IPsecPolicy");
				return -1;
			}
			if (list_empty(&ipsec_ps.hoa_list)) {
				uerror("HomeAddress missing for IPsecPolicy");
				return -1;
			}

			list_for_each(lp, &ipsec_ps.hoa_list) {
				struct home_addr_info *hai;
				struct ipsec_policy_entry *e;

				hai = list_entry(lp, struct home_addr_info,
						 list);

				e = malloc(sizeof(*e));
				if (e == NULL) {
					uerror("out of memory");
					return -1;
				}
				memset(e, 0, sizeof(*e));
				e->ha_addr = ipsec_ps.ha;
				e->mn_addr = hai->hoa.addr;
				e->type = $1;
#ifndef XFRM_MSG_MIGRATE
				switch (e->type) {
				case IPSEC_POLICY_TYPE_TUNNELHOMETESTING:
				case IPSEC_POLICY_TYPE_TUNNELMH:
				case IPSEC_POLICY_TYPE_TUNNELPAYLOAD:
					uerror("cannot use IPsec tunnel because it is not built with MIGRATE");
					return -1;
				default:
					break;
				}
#endif
#ifndef MULTIPROTO_MIGRATE
				if ($2 != IPSEC_PROTO_ESP) {
					uerror("only UseESP is allowed");
					return -1;
				}
#endif
				e->ipsec_protos = $2;
				e->reqid_toha = $3[0];
				e->reqid_tomn = $3[1];
				e->action = $4;

				if (ipsec_policy_entry_check(&e->ha_addr,
							     &e->mn_addr,
							     e->type)) {
					uerror("overlapping IPsec policies "
					       "found for "
					       "HA %x:%x:%x:%x:%x:%x:%x:%x "
					       "MN %x:%x:%x:%x:%x:%x:%x:%x "
					       "pair\n",
					       NIP6ADDR(&e->ha_addr),
					       NIP6ADDR(&e->mn_addr));
					return -1;
				}
				list_add_tail(&e->list, &conf_parsed->ipsec_policies);
			}
		}
		;

ipsectype	: IPSECPOLICY ipsectypeval { $$ = $2; }
		;

ipsectypeval	: HOMEREGBINDING { $$ = IPSEC_POLICY_TYPE_HOMEREGBINDING; }
		| MH { $$ = IPSEC_POLICY_TYPE_MH; }
		| MOBPFXDISC { $$ = IPSEC_POLICY_TYPE_MOBPFXDISC; }
		| TUNNELHOMETESTING { $$ = IPSEC_POLICY_TYPE_TUNNELHOMETESTING; }
		| TUNNELMH { $$ = IPSEC_POLICY_TYPE_TUNNELMH; }
		| TUNNELPAYLOAD { $$ = IPSEC_POLICY_TYPE_TUNNELPAYLOAD; }
		| ICMP { $$ = IPSEC_POLICY_TYPE_ICMP; }
		| ANY { $$ = IPSEC_POLICY_TYPE_ANY; }
		;

ipsecprotos	:
		{
			uerror("IPsecPolicy must set at least one protocol");
			return -1;
		}
		| ipsecproto { $$ = $1; }
		| ipsecproto ipsecproto { $$ = $1 | $2; }
		| ipsecproto ipsecproto ipsecproto { $$ = $1 | $2 | $3; }
		;

ipsecproto	: USEESP { $$ = IPSEC_PROTO_ESP; }
		| USEAH { $$ = IPSEC_PROTO_AH; }
		| USEIPCOMP { $$ = IPSEC_PROTO_IPCOMP; }
		;

ipsecreqid	: { $$[0] = $$[1] = 0; }
		| NUMBER { $$[0] = $$[1] = $1; }
		| NUMBER NUMBER { $$[0] = $1; $$[1] = $2; }
		;

xfrmaction	: { $$ = XFRM_POLICY_ALLOW; }
 		| BOOL { $$ = $1 ? XFRM_POLICY_ALLOW : XFRM_POLICY_BLOCK; }
		;

mnropolicy	: mnropolicyaddr dorouteopt
		{
			struct xfrm_ro_pol *rp;
			rp = malloc(sizeof(struct xfrm_ro_pol));
			if (rp == NULL) {
				uerror("out of memory");
				return -1;
			}
			memset(rp, 0, sizeof(struct xfrm_ro_pol));
			rp->cn_addr = $1;
			rp->do_ro = $2;
			list_add_tail(&rp->list, &hai.ro_policies);
		}
		;

mnropolicyaddr	: { $$ = in6addr_any; }
		| ADDR { $$ = $1; }
		;

dorouteopt	: BOOL { $$ = $1; }
		;

cnbindingpoldefs: cnbindingpoldef
                | cnbindingpoldefs cnbindingpoldef
                ;

cnbindingpoldef : ADDR mnropolicyaddr BOOL ';'
                {
			cnbpol = malloc(sizeof(struct cn_binding_pol_entry));
			if (cnbpol == NULL) {
				uerror("out of memory");
				return -1;
			}
			memset(cnbpol, 0, sizeof(struct cn_binding_pol_entry));
			cnbpol->remote_hoa = $1;
			cnbpol->local_addr = $2;
			cnbpol->bind_policy = $3;
			list_add_tail(&cnbpol->list,
				      &conf_parsed->cn_binding_pol);
                }
                ;
movemodule	: INTERNAL
		{
			conf_parsed->MoveModulePath = NULL;
		}
		| QSTRING
		{
			conf_parsed->MoveModulePath = NULL;
		}
		;

policymodule	: QSTRING
		{
			if (pmgr_init($1, &conf_parsed->pmgr) < 0) {
				uerror("error loading shared object %s", $1);
				return -1;
			}
		}
		;

bindaclpolval	: BOOL
		{
			if ($1)
				$$ = IP6_MH_BAS_ACCEPTED;
			else
				$$ = IP6_MH_BAS_PROHIBIT;
		}
		| NUMBER { $$ = $1; }
		;

bindaclpolicy	: ADDR prefixlistsub bindaclpolval
		{
			bae = malloc(sizeof(struct policy_bind_acl_entry));
			if (bae == NULL) {
				uerror("out of memory");
				return -1;
			}
			memset(bae, 0, sizeof(struct policy_bind_acl_entry));
			bae->hoa = $1;
			bae->plen = 128;
			INIT_LIST_HEAD(&bae->mob_net_prefixes);
			bae->mnp_count = mv_prefixes(&bae->mob_net_prefixes);
			bae->bind_policy = $3;
			list_add_tail(&bae->list, &conf_parsed->bind_acl);
		}
		;

prefixlen	: NUMBER
		{
			if ($1 > 128) {
				uerror("invalid prefix length %d", $1);
				return -1;
			}
			$$ = $1;
		}
		;

prefixlistsub	:
		| '(' prefixlist ')'
		;

prefixlist	: prefixlistentry
		| prefixlist ',' prefixlistentry
		;

prefixlistentry	: ADDR '/' prefixlen
		{
			struct prefix_list_entry *p;
			p = malloc(sizeof(struct prefix_list_entry));
			if (p == NULL) {
				fprintf(stderr,
					"%s: out of memory\n", __FUNCTION__);
				return -1;
			}
			memset(p, 0, sizeof(struct prefix_list_entry));
			p->ple_prefix = $1;
			p->ple_plen = $3;
			list_add_tail(&p->list, &prefixes);
		}
		;

prefixlen4 : NUMBER
        {
			if ($1 > 32) {
				uerror("invalid prefix length %d", $1);
				return -1;
			}
			$$ = $1;
		}
		;
prefixlistsub4	:
		| '(' prefixlist4 ')'
		;

prefixlist4	: prefixlstentry4
		| prefixlist4 ',' prefixlstentry4
		;

prefixlstentry4 : ADDR4 '/' prefixlen4
		{
			struct net_prefix4 *next = malloc(sizeof(struct net_prefix4));
			if (next == NULL) {
				fprintf(stderr, "%s: out of memory\n", 
					__FUNCTION__);
				return -1;
			}
			next->prefix4 = $1;
			next->plen4 = $3;
			next->next = NULL;
			if (hai.mnp4_count) {
				struct net_prefix4 *current_prefix4 = hai.mob_net_prefixes4;
				for (int i = 0; i < hai.mnp4_count - 1; i++) 
					current_prefix4 = current_prefix4->next;
				current_prefix4->next = next;		
			} else 
				hai.mob_net_prefixes4 = next;
			hai.mnp4_count ++;
			}
		;
		
HAprefixlistsub4	:
		| '(' HAprefixlist4 ')'
		;

HAprefixlist4	: HAprefixlstentry4
		| HAprefixlist4 ',' HAprefixlstentry4
		;

HAprefixlstentry4 : ADDR4 '/' prefixlen4
		{			
			struct net_prefix4 *next = malloc(sizeof(struct net_prefix4));
			if (next == NULL) {
				fprintf(stderr, "%s: out of memory\n", 
					__FUNCTION__);
				return -1;
			}
			next->prefix4 = $1;
			next->plen4 = $3;
			next->next = NULL;
			
			struct net_prefix4 *current = HAmnp4;
			if (HAmnp4 != NULL) {
				while (current->next != NULL) current = current->next;
				current->next = next;
			} 
			else HAmnp4 = next;
		}
		;
%%
