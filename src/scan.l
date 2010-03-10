/*
 * $Id: scan.l 1.44 06/05/12 11:48:36+03:00 vnuorval@tcs.hut.fi $
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

%top{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
}

%{
#include <arpa/inet.h>
#include <glob.h>
#include <string.h>
#include "gram.h"

#define YY_NO_INPUT 1

int lineno = 1;

static int yywrap(void) { return 1; }
void yyerror(char *s);

#define MAX_NESTED_CONF_FILES	5

struct nested_conffiles_t{
	YY_BUFFER_STATE parent_level_state;
	glob_t filelist;
	int current_file;
} nested_conffiles[MAX_NESTED_CONF_FILES];

int current_nested_level = 0;

int globerrfct(const char *epath, int eerrno)
{
	fprintf(stderr, "Failed to scan %s: %s\n", epath, strerror(eerrno));
	return 1;
}

%}

%option nounput
%option noyyget_lineno noyyset_lineno
%option noyyget_in noyyset_in
%option noyyget_out noyyset_out
%option noyyget_debug noyyset_debug
%option noyyget_leng
%option noyyget_text

%x in_include

ws		[ \t]+
comment		#.*
nl		\n
qstring		\"[^\"\n]*[\"\n]
digit		[0-9]
number		({digit})+
decimal		({number}"."{number})
hexdec		([a-f]|[A-F]|[0-9])
addr1		{hexdec}{1,4}":"({hexdec}{1,4}":")*(":"{hexdec}{1,4})+
addr2		{hexdec}{1,4}(":"{hexdec}{1,4}){0,6}"::"
addr3		({hexdec}{1,4}":"){7}{hexdec}{1,4}
addr		({addr1}|{addr2}|{addr3}|"::")
true		(enabled|allow|true)
false		(disabled|deny|block|false)
%%

include		BEGIN(in_include);
<in_include>{
{ws}		;/* skip whitespaces */
{qstring}	{ /* Name of the file to include. This is directly sent to glob. */
			int globerror=0;
			char * buf = strdup(yytext+1);
			if (buf[yyleng-2] != '"')
			{
				fprintf(stderr, "Unterminated string: %s\n", yytext);
				return INV_TOKEN;
			}
			buf[yyleng-2] = '\0';

			if (current_nested_level >= MAX_NESTED_CONF_FILES)
			{
				fprintf(stderr, "Too many recursion levels in configuration files includes\n");
				exit(1);
			}

			/* glob the include */
			globerror = glob(buf, GLOB_ERR, globerrfct, &nested_conffiles[current_nested_level].filelist);

			if (globerror == GLOB_NOSPACE)
			{
				fprintf(stderr, "Not enough memory to parse include directive.\n");
				return INV_TOKEN;
			}
			if (globerror == GLOB_ABORTED)
			{
				fprintf(stderr, "An error was encountered in include directive.\n");
				return INV_TOKEN;
			}
			if (globerror == GLOB_NOMATCH)
			{
				globfree(&nested_conffiles[current_nested_level].filelist);
				goto nomatch;
			}
			if (globerror)
			{
				fprintf(stderr, "Unexpected error in glob (%d).\n", globerror);
				return INV_TOKEN;
			}

			/* We have a list of files to include. */

			/* save the current buffer for returning when this include has been parsed */
			nested_conffiles[current_nested_level].parent_level_state = YY_CURRENT_BUFFER;

			/* Start with the first match */
			nested_conffiles[current_nested_level].current_file = 0;

			yyin = fopen( nested_conffiles[current_nested_level].filelist.gl_pathv[0], "r" );

			if ( ! yyin )
			{
				perror(nested_conffiles[current_nested_level].filelist.gl_pathv[0]);
				return INV_TOKEN;
			}

			yy_switch_to_buffer(yy_create_buffer( yyin, YY_BUF_SIZE ));

			/* In case of recursive includes */
			current_nested_level++;

nomatch:
			BEGIN(INITIAL);
		}
}
<<EOF>>		{
			if (current_nested_level == 0)
			{
				/* We are at the end of parsing */
				yyterminate();
			}

			/* Otherwise we are doing an include statement */
			--current_nested_level;
			yy_delete_buffer(YY_CURRENT_BUFFER);

			/* Go to next file, if any */
			nested_conffiles[current_nested_level].current_file++;
			if ( nested_conffiles[current_nested_level].filelist.gl_pathv[nested_conffiles[current_nested_level].current_file] == NULL )
			{
				/* We have finished with this list of includes */
				globfree(&nested_conffiles[current_nested_level].filelist);
				yy_switch_to_buffer(nested_conffiles[current_nested_level].parent_level_state);
			}
			else
			{
				/* Proceed to next included file */
				yyin = fopen( nested_conffiles[current_nested_level].filelist.gl_pathv[nested_conffiles[current_nested_level].current_file], "r" );

				if ( ! yyin )
				{
					perror(nested_conffiles[current_nested_level].filelist.gl_pathv[nested_conffiles[current_nested_level].current_file]);
					return INV_TOKEN;
				}

				yy_switch_to_buffer(yy_create_buffer( yyin, YY_BUF_SIZE ));

				/* In case of recursive includes */
				current_nested_level++;
			}

		}

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
DebugLogFile			{ return DEBUGLOGFILE; }
DoRouteOptimizationCN		{ return DOROUTEOPTIMIZATIONCN; }
DoRouteOptimizationMN		{ return DOROUTEOPTIMIZATIONMN; }
HomeAddress			{ return HOMEADDRESS; }
HomeAgentAddress		{ return HOMEAGENTADDRESS; }
InitialBindackTimeoutFirstReg	{ return INITIALBINDACKTIMEOUTFIRSTREG; }
InitialBindackTimeoutReReg	{ return INITIALBINDACKTIMEOUTREREG; }
LinkName			{ return LINKNAME; }
HaMaxBindingLife		{ return HAMAXBINDINGLIFE; }
MnMaxHaBindingLife		{ return MNMAXHABINDINGLIFE; }
MnMaxCnBindingLife		{ return MNMAXCNBINDINGLIFE; }
MaxMobPfxAdvInterval		{ return MAXMOBPFXADVINTERVAL; }
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
UseAltCoa			{ return USEALTCOA; }
UseESP				{ return USEESP; }
UseAH				{ return USEAH; }
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
MnIfPreference			{ return MNIFPREFERENCE; }
MnUseAllInterfaces     		{ return MNUSEALLINTERFACES; }
MnRouterProbes			{ return MNROUTERPROBES; }
MnRouterProbeTimeout		{ return MNROUTERPROBETIMEOUT; }
MnDiscardHaParamProb		{ return MNDISCARDHAPARAMPROB; }
OptimisticHandoff		{ return OPTIMISTICHANDOFF; }
HaAcceptMobRtr   		{ return HAACCEPTMOBRTR; }
IsMobRtr       			{ return ISMOBRTR; }
HaServedPrefix       	       	{ return HASERVEDPREFIX; }
HomePrefix     			{ return HOMEPREFIX; }
MobRtrUseExplicitMode    	{ return MOBRTRUSEEXPLICITMODE; }
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
