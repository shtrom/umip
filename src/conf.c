/*
 * $Id: conf.c 1.33 05/12/06 18:19:34+02:00 vnuorval@tcs.hut.fi $
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#ifdef HAVE_NETINET_IP6MH_H
#include <netinet/ip6mh.h>
#else
#include <netinet-ip6mh.h>
#endif
#include "defpath.h"
#include "conf.h"
#include "debug.h"
#include "util.h"
#include "mipv6.h"
#ifdef ENABLE_VT
#include "vt.h"
#endif

static void conf_usage(char *exec_name)
{
	fprintf(stderr,
		"Usage: %s [options]\nOptions:\n"
		"  -V, --version            Display version information and copyright\n"
		"  -?, -h, --help           Display this help text\n"
		"  -c <file>                Read configuration from <file>\n"
#ifdef ENABLE_VT
		"      --vt-service <serv>  Set VT service (default=" VT_DEFAULT_SERVICE ")\n"
#endif
		"\n These options override values read from config file:\n"
		"  -d <number>              Set debug level (0-10)\n"
		"  -C, --correspondent-node Node is CN\n"
		"  -H, --home-agent         Node is HA\n"
		"  -M, --mobile-node        Node is MN\n\n"
		"For bug reporting, see %s.\n",
		exec_name, PACKAGE_BUGREPORT);
}

static void conf_version(void)
{
	fprintf(stderr,
		"%s (%s) %s\n"
		"%s\n"
		"This is free software; see the source for copying conditions.  There is NO\n"
		"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
		PACKAGE, PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_COPYRIGHT);
}

static int conf_alt_file(char *filename, int argc, char **argv)
{
	int args_left = argc;
	char **cur_arg = argv;

	while (args_left--) {
		if (strcmp(*cur_arg, "-c") == 0 && args_left > 0) {
			cur_arg++;
			if (**cur_arg == '-')
				return -EINVAL;
			if (strlen(*cur_arg) >= MAXPATHLEN)
				return -ENAMETOOLONG;
			strcpy(filename, *cur_arg);
			return 0;
		}
		cur_arg++;
	}

	return 1;
}

static int conf_file(struct mip6_config *c, char *filename)
{
	extern FILE *yyin;
	int ret;

	yyin = fopen(filename, "r");
	if (yyin == NULL)
		return -ENOENT;

	c->config_file = malloc(strlen(filename) + 1);
	if (c->config_file == NULL)
		return -ENOMEM;
	strcpy(c->config_file, filename);

	ret = yyparse();

	fclose(yyin);

	if (ret) return -EINVAL;

	return 0;
}

static int conf_cmdline(struct mip6_config *cfg, int argc, char **argv)
{
	static struct option long_opts[] = {
		{"version", 0, 0, 'V'},
		{"help", 0, 0, 'h'},
		{"correspondent-node", 0, 0, 'C'},
		{"home-agent", 0, 0, 'H'},
		{"mobile-node", 0, 0, 'M'},
		{"show-config", 0, 0, 0},
#ifdef ENABLE_VT
		{"vt-service", 1, 0, 0 },
#endif
		{0, 0, 0, 0}
	};

	/* parse all other cmd line parameters than -c */
	while (1) {
		int idx, c;
		c = getopt_long(argc, argv, "c:d:Vh?CMH", long_opts, &idx);
		if (c == -1) break;

		switch (c) {
		case 0:
#ifdef ENABLE_VT
			if (strcmp(long_opts[idx].name, "vt-service") == 0) {
				cfg->vt_service = optarg;
				break;
			}
#endif
			if (idx == 5)
				conf_show(cfg);
			return -1;
		case 'V':
			conf_version();
			return -1;
		case '?':
		case 'h':
			conf_usage(basename(argv[0]));
			return -1;
		case 'd':
			cfg->debug_level = atoi(optarg);
			break;
		case 'C':
			cfg->mip6_entity = MIP6_ENTITY_CN;
			break;
		case 'H':
			cfg->mip6_entity = MIP6_ENTITY_HA;
			break;
		case 'M':
			cfg->mip6_entity = MIP6_ENTITY_MN;
			break;
		default:
			break;
		};
	}
	return 0;
}

static void conf_default(struct mip6_config *c)
{
	c->mip6_entity = MIP6_ENTITY_CN;
	c->debug_level = 0;
#ifdef ENABLE_VT
	c->vt_hostname = VT_DEFAULT_HOSTNAME;
	c->vt_service = VT_DEFAULT_SERVICE;
#endif
	c->NonVolatileBindingCache = 0; /* future */
	c->SendUnsolMobPfxAdvs = 1;
	c->SendMobPfxAdvs = 1;
	c->SendMobPfxSols = 1;
	c->MaxMobPfxAdvInterval = 86400; /* seconds */
	c->MinMobPfxAdvInterval = 600; /* seconds */
	tssetsec(c->MinDelayBetweenRAs_ts, 3); /* seconds */
	c->DoRouteOptimizationCN = 1;
	c->DoRouteOptimizationMN = 1;
	c->MaxBindingLife = MAX_BINDING_LIFETIME;
	tssetdsec(c->InitialBindackTimeoutFirstReg_ts, 1.5);/*seconds*/
	tssetsec(c->InitialBindackTimeoutReReg_ts, INITIAL_BINDACK_TIMEOUT);/*seconds*/
	c->InitialSolicitTimer = 3; /* seconds */
	c->UseMnHaIPsec = 1;
	c->KeyMngMobCapability = 0;
	c->MoveModulePath = NULL; /* internal */
	c->DefaultBindingAclPolicy = IP6_MH_BAS_ACCEPTED;
	c->UseCnBuAck = 0;
	c->MnUseAllInterfaces = 0;
	c->MnRouterProbesRA = 0;
	c->MnRouterProbesLinkUp = 0;
	pmgr_init(NULL, &conf.pmgr);
	INIT_LIST_HEAD(&c->home_addrs);
	INIT_LIST_HEAD(&c->ipsec_policies);
	INIT_LIST_HEAD(&c->bind_acl);
	INIT_LIST_HEAD(&c->net_ifaces);
}

int conf_parse(struct mip6_config *c, int argc, char **argv)
{
	char cfile[MAXPATHLEN];
	int ret;

	/* set config defaults */
	conf_default(c);

	if ((ret = conf_alt_file(cfile, argc, argv)) != 0) {
		if (ret == -EINVAL) {
			fprintf(stderr,
				"%s: option requires an argument -- c\n",
				argv[0]);
			conf_usage(basename(argv[0]));
			exit(errno);
		} else if (ret == -ENAMETOOLONG) {
			fprintf(stderr,
				"%s: argument too long -- c <file>\n",
				argv[0]);
			exit(errno);
		}
		strcpy(cfile, DEFAULT_CONFIG_FILE);
	}

	if (conf_file(c, cfile) < 0 && ret == 0) {
		fprintf(stderr,
			"%s: file error: could not parse file \"%s\".\n",
			argv[0], cfile);
		exit(errno);
	}

	if (conf_cmdline(c, argc, argv) < 0)
		return -1;

	return 0;
}

void conf_show(struct mip6_config *c)
{
	dbg("config_file = %s\n", c->config_file);
	dbg("mip6_entity = %d\n", c->mip6_entity);
	dbg("debug_level = %d\n", c->debug_level);
#ifdef ENABLE_VT
	dbg("vt_hostname = %s\n", c->vt_hostname);
	dbg("vt_service = %s\n", c->vt_service);
#endif
	dbg("NonVolatileBindingCache = %d\n", c->NonVolatileBindingCache);
	dbg("SendUnsolMobPfxAdvs = %d\n", c->SendUnsolMobPfxAdvs);
	dbg("SendMobPfxAdvs = %d\n", c->SendMobPfxAdvs);
	dbg("SendMobPfxSols = %d\n", c->SendMobPfxSols);
	dbg("MaxMobPfxAdvInterval = %d\n", c->MaxMobPfxAdvInterval);
	dbg("MinMobPfxAdvInterval = %d\n", c->MinMobPfxAdvInterval);
	dbg("MinDelayBetweenRAs = %d.%d\n", 
	    c->MinDelayBetweenRAs_ts.tv_sec, 
	    c->MinDelayBetweenRAs_ts.tv_nsec);
	dbg("DoRouteOptimizationCN = %d\n", c->DoRouteOptimizationCN);
	dbg("DoRouteOptimizationMN = %d\n", c->DoRouteOptimizationMN);
	dbg("MaxBindingLife = %d\n", c->MaxBindingLife);
	dbg("InitialBindackTimeoutFirstReg = %d.%d\n", 
	    c->InitialBindackTimeoutFirstReg_ts.tv_sec,
	    c->InitialBindackTimeoutFirstReg_ts.tv_nsec);
	dbg("InitialBindackTimeoutReReg = %d.%d\n", 
	    c->InitialBindackTimeoutReReg_ts.tv_sec,
	    c->InitialBindackTimeoutReReg_ts.tv_nsec);
	dbg("UseMnHaIPsec = %d\n", c->UseMnHaIPsec);
	dbg("KeyMngMobCapability = %d\n", c->KeyMngMobCapability);
	if (c->MoveModulePath)
		dbg("MoveModulePath = %s\n", c->MoveModulePath);
	dbg("PolicyModulePath = %s\n", c->pmgr.so_path);
}
