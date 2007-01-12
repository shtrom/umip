/* $Id: conf.h 1.26 05/12/07 21:47:54+02:00 vnuorval@tcs.hut.fi $ */

#ifndef __CONF_H__
#define __CONF_H__ 1

#include <time.h>
#include <net/if.h>
#include "list.h"
#include "pmgr.h"

struct mip6_config {
	char *config_file;
	int mip6_entity;
	int debug_level;
#ifdef ENABLE_VT
	char *vt_hostname;
	char *vt_service;
#endif
	int NonVolatileBindingCache;
	int SendUnsolMobPfxAdvs;
	int SendMobPfxAdvs;
	int SendMobPfxSols;
	unsigned int MaxMobPfxAdvInterval;
	unsigned int MinMobPfxAdvInterval;
	struct timespec MinDelayBetweenRAs_ts;
	int DoRouteOptimizationCN;
	int DoRouteOptimizationMN;
	int MaxBindingLife;
	struct timespec InitialBindackTimeoutFirstReg_ts;
	struct timespec InitialBindackTimeoutReReg_ts;
	int InitialSolicitTimer;
	int UseMnHaIPsec;
	int KeyMngMobCapability;
	int DefaultBindingAclPolicy;
	int UseCnBuAck;
	int MnUseAllInterfaces;
	int MnRouterProbesRA;
	int MnRouterProbesLinkUp;
	char *MoveModulePath;
	struct pmgr_cb pmgr;
	struct list_head home_addrs;
	struct list_head ipsec_policies;
	struct list_head bind_acl;
	struct list_head net_ifaces;
	struct timespec MnRouterProbeTimeout_ts;
};

struct net_iface {
	struct list_head list;
	char name[IF_NAMESIZE];
	int ifindex;
	int is_rtr;
	int mip6_if_entity;
	int mn_if_preference;
};

extern struct mip6_config conf;

#define MIP6_ENTITY_CN 0
#define MIP6_ENTITY_MN 1
#define MIP6_ENTITY_HA 2

static inline int is_cn(void)
{
	return conf.mip6_entity == MIP6_ENTITY_CN;
}

static inline int is_mn(void)
{
	return conf.mip6_entity == MIP6_ENTITY_MN;
}

static inline int is_ha(void)
{
	return conf.mip6_entity == MIP6_ENTITY_HA;
}

int conf_parse(struct mip6_config *c, int argc, char **argv);

void conf_show(struct mip6_config *c);

int yyparse(void);

int yylex(void);

#endif
