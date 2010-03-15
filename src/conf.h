/* $Id: conf.h 1.39 06/05/12 11:48:36+03:00 vnuorval@tcs.hut.fi $ */

#ifndef __CONF_H__
#define __CONF_H__ 1

#include <time.h>
#include <net/if.h>
#include "list.h"
#include "pmgr.h"
#include "dhcp_dna.h"

struct mip6_config {
	/* Common options */
	char *config_file;
#ifdef ENABLE_VT
	char *vt_hostname;
	char *vt_service;
#endif
	unsigned int mip6_entity;
	unsigned int debug_level;
	char *debug_log_file;
	struct pmgr_cb pmgr;
	struct list_head net_ifaces;
	struct list_head bind_acl;
	uint8_t DefaultBindingAclPolicy;
	char NonVolatileBindingCache;

	/* IPsec options */
	char KeyMngMobCapability;
	char TunnelPayloadForceSANego;
	char UseMnHaIPsec;
	struct list_head ipsec_policies;

	/* MN options */
	unsigned int MnMaxHaBindingLife;
	unsigned int MnMaxCnBindingLife;
	unsigned int MnRouterProbes;
	struct timespec MnRouterProbeTimeout_ts;
	struct timespec InitialBindackTimeoutFirstReg_ts;
	struct timespec InitialBindackTimeoutReReg_ts;
	struct timespec InitialSolicitTimer_ts;
	struct list_head home_addrs;
	char *MoveModulePath;
	uint16_t CnBuAck;
	char MobRtrUseExplicitMode;
	char DoRouteOptimizationMN;
	char MnUseAllInterfaces;
	char MnDiscardHaParamProb;
	char SendMobPfxSols;
	char OptimisticHandoff;
	char MnUseDsmip6;
	char MnSupportIPv4Traffic;

	/* HA options */
	char HaAcceptMobRtr;
	char SendMobPfxAdvs;
	char SendUnsolMobPfxAdvs;
	unsigned int MaxMobPfxAdvInterval;
	unsigned int MinMobPfxAdvInterval;
	unsigned int HaMaxBindingLife;
	struct list_head nemo_ha_served_prefixes;
	char HaAcceptDsmip6;
	struct in6_addr HaAddr4Mapped;
	int home_plen4;
	struct hoa4_mnp4 *mnpv4;

	/* CN options */
	char DoRouteOptimizationCN;
	struct list_head cn_binding_pol;
};

struct net_iface {
	struct list_head list;
	char name[IF_NAMESIZE];
	int ifindex;
	int is_rtr;
	int mip6_if_entity;
	int mn_if_preference;
	int is_tunnel;
	struct dhcp_dna_control_s *dhcp_ctrl;
};

struct iface_ready {
	char have_addr;
	int iif;
};

extern struct mip6_config conf;
extern struct mip6_config *conf_parsed;

extern struct iface_ready iface_have_addr[];

#define MIP6_ENTITY_NO -1
#define MIP6_ENTITY_CN 0
#define MIP6_ENTITY_MN 1
#define MIP6_ENTITY_HA 2
#define MAX_INTERFACE_INDEX 256

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

static inline int is_if_entity_set(struct net_iface *i)
{
	return i->mip6_if_entity != MIP6_ENTITY_NO;

}

static inline int is_if_cn(struct net_iface *i)
{
	return (is_cn() &&
		(!is_if_entity_set(i) || i->mip6_if_entity == MIP6_ENTITY_CN));

}

static inline int is_if_mn(struct net_iface *i)
{
	return (is_mn() &&
		(!is_if_entity_set(i) || i->mip6_if_entity == MIP6_ENTITY_MN));
}

static inline int is_if_ha(struct net_iface *i)
{
	return (is_ha() &&
		(!is_if_entity_set(i) || i->mip6_if_entity == MIP6_ENTITY_HA));
}

int conf_parse(struct mip6_config *c, int argc, char **argv);

void conf_show(struct mip6_config *c);

void set_iface_have_addr(int iif, char value);

char is_iface_have_addr(int iif);

void add_iface_have_addr(int iif);

char all_iface_down();

int yyparse(void);

int yylex(void);

int conf_update(struct mip6_config *c, void (*apply_changes_cb)(struct mip6_config *, struct mip6_config *));

#endif
