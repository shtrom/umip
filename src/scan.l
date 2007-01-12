/*
 * $Id: scan.l 1.29 05/12/07 15:19:30+02:00 vnuorval@tcs.hut.fi $
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
#include <string.h>
#include <arpa/inet.h>
#include "gram.h"

#define YY_NO_UNPUT 1

int lineno = 1;

static int yywrap(void) { return 1; }
void yyerror(char *s);

%}

ws		[ \t]+
comment		#.*
nl		\n
qstring		\"[^\"\n]*[\"\n]
digit		[0-9]
unumber		({digit})+
number		[+-]?({unumber})
udecimal	({unumber}"."{unumber})
decimal		[+-]?({udecimal})
hexdec		([a-f]|[A-F]|[0-9])
addr1		{hexdec}{1,4}":"({hexdec}{1,4}":")*(":"{hexdec}{1,4})+
addr2		{hexdec}{1,4}(":"{hexdec}{1,4}){0,6}"::"
addr3		({hexdec}{1,4}":"){7}{hexdec}{1,4}
addr		({addr1}|{addr2}|{addr3}|"::")
true		(enabled|allow|true)
false		(disabled|deny|block|false)
%%

{ws}		;
{comment}	;
{nl}		{ lineno++; }
{qstring}	{
			yylval.string = strdup(yytext+1);
			if (yylval.string[yyleng-2] != '"')
				fprintf(stderr, "Unterminated string\n");
			else
				yylval.string[yyleng-2] = '\0';
			return QSTRING;
		}

NodeConfig			{ return MIP6ENTITY; }
HA				{ return MIP6HA; }
CN				{ return MIP6CN; }
MN				{ return MIP6MN; }
DebugLevel			{ return DEBUGLEVEL; }
DoRouteOptimizationCN		{ return DOROUTEOPTIMIZATIONCN; }
DoRouteOptimizationMN		{ return DOROUTEOPTIMIZATIONMN; }
HomeAddress			{ return HOMEADDRESS; }
HomeAgentAddress		{ return HOMEAGENTADDRESS; }
InitialBindackTimeoutFirstReg	{ return INITIALBINDACKTIMEOUTFIRSTREG; }
InitialBindackTimeoutReReg	{ return INITIALBINDACKTIMEOUTREREG; }
LinkName			{ return LINKNAME; }
MaxBindingLife			{ return MAXBINDINGLIFE; }
MaxMobPfxAdvInterval		{ return MAXMOBPFXADVINTERVAL; }
MinDelayBetweenRAs		{ return MINDELAYBETWEENRAS; }
MinMobPfxAdvInterval		{ return MINMOBPFXADVINTERVAL; }
MnHomeLink			{ return MNHOMELINK; }
NonVolatileBindingCache		{ return NONVOLATILEBINDINGCACHE; }
SendMobPfxSols			{ return SENDMOBPFXSOLS; }
SendUnsolMobPfxAdvs	       	{ return SENDUNSOLMOBPFXADVS; }
SendMobPfxAdvs			{ return SENDMOBPFXADVS; }
UseMovementModule		{ return USEMOVEMENTMODULE; }
UsePolicyModule			{ return USEPOLICYMODULE; }
IPsecPolicySet			{ return IPSECPOLICYSET; }
IPsecPolicy			{ return IPSECPOLICY; }
IPsecType			{ return IPSECTYPE; }
NoAH				{ return NOAH; }
UseAH				{ return USEAH; }
UseAltCoa			{ return USEALTCOA; }
NoESP				{ return NOESP; }
UseESP				{ return USEESP; }
NoIPComp			{ return NOIPCOMP; }
UseIPComp			{ return USEIPCOMP; }
UseMnHaIPsec			{ return USEMNHAIPSEC; }
KeyMngMobCapability		{ return KEYMNGMOBCAPABILITY; }
HomeRegBinding			{ return HOMEREGBINDING; }
Mh				{ return MH; }
MobPfxDisc			{ return MOBPFXDISC; }
TunnelHomeTesting		{ return TUNNELHOMETESTING; }
TunnelMh			{ return TUNNELMH; }
TunnelPayload			{ return TUNNELPAYLOAD; }
MnRoPolicy       		{ return MNROPOLICY; }
ICMP				{ return ICMP; }
any				{ return ANY; }
DoRouteOptimization		{ return DOROUTEOPT; }
DefaultBindingAclPolicy		{ return DEFAULTBINDINGACLPOLICY; }
BindingAclPolicy		{ return BINDINGACLPOLICY; }
UseCnBuAck			{ return USECNBUACK; }
Interface			{ return INTERFACE; }
IfName				{ return IFNAME; }
IfType				{ return IFTYPE; }
IsRouter			{ return ISROUTER; }
MnIfPreference			{ return MNIFPREFERENCE; }
MnUseAllInterfaces     		{ return MNUSEALLINTERFACES; }
MnRouterProbesRA		{ return MNROUTERPROBESRA; }
MnRouterProbesLinkUp		{ return MNROUTERPROBESLINKUP; }
MnRouterProbeTimeout		{ return MNROUTERPROBETIMEOUT; }
internal			{ return INTERNAL; }

{addr}		{
			int i;
				
			i = inet_pton(AF_INET6, yytext, &yylval.addr);

			if (i < 1) {
				return INV_TOKEN;
			}
			return ADDR;
		}

{number}	{ yylval.num = atoi(yytext); return NUMBER; }

{decimal}	{ yylval.dec = atof(yytext); return DECIMAL; }

{true}  	{ yylval.bool = 1; return BOOL; }

{false} 	{ yylval.bool = 0; return BOOL; }

"{"|"}"|";"|"/"|"="|"("|")"|","	{ return *yytext; }

.		{ return INV_TOKEN; }
%%
