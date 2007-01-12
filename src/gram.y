/*
 * $Id: gram.y 1.69 06/01/10 00:07:47+09:00 nakam@linux-ipv6.org $
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
 * 02111-1307 USA
 */

%{

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#else
#error "POSIX Thread Library required!"
#endif
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_NETINET_IP6MH_H
#include <netinet/ip6mh.h>
#else
#include <netinet-ip6mh.h>
#endif
#include "mipv6.h"
#include "ha.h"
#include "mn.h"
#include "conf.h"
#include "policy.h"
#include "xfrm.h"
#include "prefix.h"
#include "util.h"
#include "ipsec.h"
#include "rtnl.h"

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP   132
#endif

struct net_iface ni = {
	.mip6_if_entity = -1,
	.mn_if_preference = POL_MN_IF_DEF_PREFERENCE,
};
	
struct home_addr_info hai = {
	.ro_policies = LIST_HEAD_INIT(hai.ro_policies)
};

struct policy_bind_acl_entry *bae = NULL;

struct ipsec_policy_set {
	struct in6_addr ha;
	struct list_head hoa_list;
};

struct ipsec_policy_set ipsec_ps = {
	.hoa_list = LIST_HEAD_INIT(ipsec_ps.hoa_list)
};

extern int lineno;
extern char *yytext;

void yyerror(char *s) {
	fprintf(stderr, "Error in configuration file %s\n", conf.config_file);
	fprintf(stderr, "line %d: %s at '%s'\n", lineno, s, yytext);
}

void uerror(const char *fmt, ...) {
	char s[1024];
	va_list args;

	fprintf(stderr, "Error in configuration file %s\n", conf.config_file);
	va_start(args, fmt);
	vsprintf(s, fmt, args);
	fprintf(stderr, "line %d: %s\n", lineno, s);
	va_end(args);
}

%}

%union {
	char *string;
	struct in6_addr addr;
	int bool;
	int num;
	double dec;
}

%token <string> QSTRING
%token <addr>	ADDR
%token <bool>	BOOL
%token <num>	NUMBER
%token <dec>	DECIMAL

%token		MIP6ENTITY
%token		DEBUGLEVEL
%token		DOROUTEOPTIMIZATIONCN
%token		DOROUTEOPTIMIZATIONMN
%token		HOMEADDRESS
%token		HOMEAGENTADDRESS
%token		INITIALBINDACKTIMEOUTFIRSTREG
%token		INITIALBINDACKTIMEOUTREREG
%token		LINKNAME
%token		MAXBINDINGLIFE
%token		MAXMOBPFXADVINTERVAL
%token		MINDELAYBETWEENRAS
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
%token		NOAH
%token		USEAH
%token		USEALTCOA
%token		NOESP
%token		USEESP
%token		NOIPCOMP
%token		USEIPCOMP
%token		BLOCK
%token		USEMNHAIPSEC
%token		KEYMNGMOBCAPABILITY
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
%token		ISROUTER
%token		MNIFPREFERENCE
%token		MNUSEALLINTERFACES
%token		MNROUTERPROBESRA
%token		MNROUTERPROBESLINKUP
%token		MNROUTERPROBETIMEOUT

%token		INV_TOKEN

%type <num>	ipsectype
%type <num>	ipsectypeval
%type <num>	ipsecproto
%type <num>	ipsecprotos
%type <num>	ipsecreqid

%type <addr>	mnropolicyaddr
%type <bool>	dorouteopt
%type <num>	bindaclpolval
%type <num>	prefixlen
%type <num>	mip6entity
%type <bool>	xfrmaction
%type <num>	unumber
%type <dec>	udecimal

%%

grammar		: topdef
		| grammar topdef
		;

topdef		: MIP6ENTITY mip6entity ';'
		{
			conf.mip6_entity = $2;
		}
		| DEBUGLEVEL NUMBER ';'
		{
			conf.debug_level = $2;
		}
		| NONVOLATILEBINDINGCACHE BOOL ';'
		{
			conf.NonVolatileBindingCache = $2;
		}
		| INTERFACE ifacedef
		| SENDMOBPFXSOLS BOOL ';'
		{
			conf.SendMobPfxSols = $2;
		}
		| SENDUNSOLMOBPFXADVS BOOL ';'
		{
			conf.SendUnsolMobPfxAdvs = $2;
		}
		| SENDMOBPFXADVS BOOL ';'
		{
			conf.SendMobPfxAdvs = $2;
		}
		| MAXMOBPFXADVINTERVAL unumber ';'
		{
			conf.MaxMobPfxAdvInterval = $2;
		}
		| MINMOBPFXADVINTERVAL unumber ';'
		{
			conf.MinMobPfxAdvInterval = $2;
		}
		| MINDELAYBETWEENRAS udecimal ';'
		{
			tssetdsec(conf.MinDelayBetweenRAs_ts, $2);
		}
		| DOROUTEOPTIMIZATIONCN BOOL ';'
		{
			conf.DoRouteOptimizationCN = $2;
		}
		| DOROUTEOPTIMIZATIONMN BOOL ';'
		{
			conf.DoRouteOptimizationMN = $2;
		}
		| MAXBINDINGLIFE unumber ';'
		{
			if ($2 > MAX_BINDING_LIFETIME) {
				uerror("invalid max binding lifetime");
				return -1;
			}
			conf.MaxBindingLife = $2;
		}
		| INITIALBINDACKTIMEOUTFIRSTREG udecimal ';'
		{
			tssetdsec(conf.InitialBindackTimeoutFirstReg_ts, $2);
		}
		| INITIALBINDACKTIMEOUTREREG udecimal ';'
		{
			tssetdsec(conf.InitialBindackTimeoutReReg_ts, $2);
		}
		| MNHOMELINK linksub
		| USEMNHAIPSEC BOOL ';'
		{
			conf.UseMnHaIPsec = $2;
		}
		| KEYMNGMOBCAPABILITY BOOL  ';'
		{
			conf.KeyMngMobCapability = $2;
		}
		| USEMOVEMENTMODULE movemodule ';'
		| USEPOLICYMODULE policymodule ';'
		| DEFAULTBINDINGACLPOLICY bindaclpolval ';'
		{
			conf.DefaultBindingAclPolicy = $2;
		}
		| BINDINGACLPOLICY bindaclpolicy ';' 
		{
			bae = NULL;
		}
		| USECNBUACK BOOL ';' 
		{
			conf.UseCnBuAck = $2;
		}
		| IPSECPOLICYSET '{' ipsecpolicyset '}'
		| MNUSEALLINTERFACES BOOL ';' 
		{
			conf.MnUseAllInterfaces = $2;
		}
		| MNROUTERPROBESRA unumber ';' 
		{
			conf.MnRouterProbesRA = $2;
		}
		| MNROUTERPROBESLINKUP unumber ';' 
		{
			conf.MnRouterProbesLinkUp = $2;
		}
		| MNROUTERPROBETIMEOUT udecimal ';' 
		{
			if ($2 > 0)
				tssetdsec(conf.MnRouterProbeTimeout_ts, $2);
		}
		;

mip6entity	: MIP6CN { $$ = MIP6_ENTITY_CN;	}
		| MIP6MN { $$ = MIP6_ENTITY_MN; }
		| MIP6HA { $$ = MIP6_ENTITY_HA; }
		;

ifacedef	: QSTRING ifacesub
		{
			struct net_iface *nni;
			if (ni.mip6_if_entity == -1)
				ni.mip6_if_entity = conf.mip6_entity;

			strncpy(ni.name, $1, IF_NAMESIZE - 1);
			ni.ifindex = if_nametoindex($1);
			free($1);
			if (ni.ifindex <= 0) {
				uerror("invalid interface");
				return -1;
			}
			nni = malloc(sizeof(struct net_iface));
			if (nni == NULL) {
				uerror("out of memory");
				return -1;
			}


			memcpy(nni, &ni, sizeof(struct net_iface));
			list_add_tail(&nni->list, &conf.net_ifaces);
			if (ni.mip6_if_entity == MIP6_ENTITY_HA && ni.ifindex)
				homeagent_if_init(ni.ifindex);

			memset(&ni, 0, sizeof(struct net_iface));
			ni.mip6_if_entity = -1;
			ni.mn_if_preference = POL_MN_IF_DEF_PREFERENCE;
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
		| ISROUTER BOOL ';'
		{
			ni.is_rtr = $2;
		}
		| MNIFPREFERENCE NUMBER ';'
		{
			ni.mn_if_preference = $2;
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
			nhai->ha_list.dhaad_id = -1;
			list_splice(&hai.ro_policies, &nhai->ro_policies);
			list_add_tail(&nhai->list, &conf.home_addrs);

			memset(&hai, 0, sizeof(struct home_addr_info));
			INIT_LIST_HEAD(&hai.ro_policies);
		}
		;

linkdefs	: linkdef
		| linkdefs linkdef
		;

linkdef		: HOMEAGENTADDRESS ADDR ';'
		{
			memcpy(&hai.ha_addr, &$2, sizeof(struct in6_addr));
		}
		| HOMEADDRESS ADDR '/' prefixlen ';'
		{
			hai.hoa.addr = $2;
			hai.plen = $4;
		}
		| USEALTCOA BOOL ';'
                {
		        hai.altcoa = $2;
		}	  
		| MNROPOLICY mnropolicy ';'
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

ipsecpolicydef	: ipsectype ipsecprotos ipsecreqid ipsecreqid xfrmaction ';'
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
				if ($2 & 1)
					e->use_esp = 1;
	 			if ($2 & 2)
					e->use_ah = 1;
				if ($2 & 4)
					e->use_ipcomp = 1;
				if ($3 == -1 && $4 == -1) {
					e->reqid_toha = 0;
					e->reqid_tomn = 0;
				} else if ($3 == -1) {
					e->reqid_toha = $4;
					e->reqid_tomn = $4;
				} else if ($4 == -1) {
					e->reqid_toha = $3;
					e->reqid_tomn = $3;
				} else {
					e->reqid_toha = $3;
					e->reqid_tomn = $4;
				}
				e->action = $5;

				/* XXX: Todo: validation required not to add
				 * duplicated entry. */
				list_add_tail(&e->list, &conf.ipsec_policies);
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
		| ipsecproto ipsecproto { $$ = $1 + $2; }
		| ipsecproto ipsecproto ipsecproto { $$ = $1 + $2 + $3; }
		;

ipsecproto	: USEESP { $$ = 1; }
		| NOESP { $$ = 0; }
		| USEAH { $$ = 2; }
		| NOAH { $$ = 0; }
		| USEIPCOMP { $$ = 4; }
		| NOIPCOMP { $$ = 0; }
		;

ipsecreqid	: { $$ = -1; }
		| unumber { $$ = $1; }
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

movemodule	: INTERNAL
		{
			conf.MoveModulePath = NULL;
		}
		| QSTRING
		{
			conf.MoveModulePath = NULL;
		}
		;

policymodule	: QSTRING
		{
			if (pmgr_init($1, &conf.pmgr) < 0) {
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
		| unumber { $$ = $1; }
		;

bindaclpolicy	: ADDR bindaclpolval
		{
			bae = malloc(sizeof(struct policy_bind_acl_entry));
			if (bae == NULL) {
				uerror("out of memory");
				return -1;
			}
			memset(bae, 0, sizeof(struct policy_bind_acl_entry)); 
			bae->hoa = $1;
			bae->plen = 128;
			bae->bind_policy = $2;
			list_add_tail(&bae->list, &conf.bind_acl);
		}
		;

prefixlen	: unumber 
		{
			if ($1 > 128) {
				uerror("invalid prefix length %d", $1);
				return -1;
			}
			$$ = $1;
		}
		;

unumber	 	: NUMBER 
		{
			if ($1 < 0) {
				uerror("negative value %d not valid", $1);
				return -1;
			}
			$$ = $1;
		}
		;

udecimal	: DECIMAL 
		{
			if ($1 < 0) {
				uerror("negative value %d not valid", $1);
				return -1;
			}
			$$ = $1;
		}
		;

%%
