/*
 * $Id: bul.c 1.95 05/12/12 17:59:16+02:00 vnuorval@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 *
 * Author: Henrik Petander <petander@tcs.hut.fi>
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
#include <time.h>
#include <errno.h>
#ifdef HAVE_NETINET_IP6MH_H
#include <netinet/ip6mh.h>
#else
#include <netinet-ip6mh.h>
#endif
#include <syslog.h>

#include "bul.h"
#include "mn.h"
#include "util.h"
#include "xfrm.h"
#include "debug.h"
#ifdef ENABLE_VT
#include "vt.h"
#endif

#define BUL_DEBUG_LEVEL 1

#if BUL_DEBUG_LEVEL >= 1
#define BDBG dbg
#else
#define BDBG(...)
#endif

#define BUL_BUCKETS 32

static struct hash bul_hash;

struct bulentry *create_bule(struct in6_addr *cn_addr)
{
	struct bulentry *bule;
	if ((bule = malloc(sizeof(*bule))) != NULL) {
		memset(bule, 0, sizeof(*bule));
		INIT_LIST_HEAD(&bule->rr.home_addrs);
		INIT_LIST_HEAD(&bule->tqe.list);
		bule->seq = random();
	}
	return bule;
}

void free_bule(struct bulentry *bule)
{
	assert(bule != NULL);
	free(bule);
}

void dump_bule(struct bulentry *bule)
{
	BDBG("******* [%p] *******\n", bule);
	BDBG("coa = %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&bule->coa));
	BDBG("hoa = %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(&bule->hoa));
	BDBG("CN address = %x:%x:%x:%x:%x:%x:%x:%x\n",
	     NIP6ADDR(&bule->peer_addr));
	BDBG(" lifetime = %d, ", bule->lifetime.tv_sec);
	BDBG("delay = %d\n", tstomsec(bule->delay));
	BDBG("flags: ");
	if (bule->flags & IP6_MH_BU_HOME)
		BDBG("IP6_MH_BU_HOME ");
	if (bule->flags & IP6_MH_BU_ACK)
		BDBG("IP6_MH_BU_ACK ");
	if (bule->flags & IP6_MH_BU_KEYM)
		BDBG("IP6_MH_BU_KEYM");
	BDBG("\n");
	if (bule->type == BUL_ENTRY)
		BDBG("type = BUL_ENTRY\n");
	else if (bule->type == HOT_ENTRY)
		BDBG("type = HOT_ENTRY\n");
	else if (bule->type == COT_ENTRY)
		BDBG("type = COT_ENTRY\n");
	else if (bule->type == NON_MIP_CN_ENTRY)
		BDBG("type = NON_MIP_CN_ENTRY\n");
	else 
		BDBG("Unknown type\n");
}

/**
 * bul_get - returns a binding update list entry
 * @hinfo: home address info, optional if our_addr is present
 * @our_addr: local address (home address)
 * @peer_addr: address of CN
 *
 * Returns non-null entry on success and null on failure. Caller must
 * call del_task and add_task, if lifetime of the entry is changed.
 **/
struct bulentry *bul_get(struct home_addr_info *hinfo,
			 const struct in6_addr *our_addr,
			 const struct in6_addr *peer_addr)
{
	struct bulentry *bule;

	assert(hinfo || our_addr);

	if (hinfo)
		bule = hash_get(&hinfo->bul, NULL, peer_addr);
	else bule = hash_get(&bul_hash, our_addr, peer_addr);
	return bule;
}

/*
 * need to be separated into two phase:
 * phase 1: before sending BU
 * 		add policy/state for BU
 * phase 2: after sending BU
 * 		add policy/state for RO
 */
void bul_update_timer(struct bulentry *bule)
{
	struct timespec timer_expire;

	BDBG("******* [%p] *******\n", bule);
	tsadd(bule->delay, bule->lastsent, timer_expire);
	add_task_abs(&timer_expire, &bule->tqe, bule->callback);
}

void bul_update_expire(struct bulentry *bule)
{

	BDBG("******* [%p] *******\n", bule);
	bule->expires = bule->lastsent;
	if (tsisset(bule->lifetime))
		tsadd(bule->lastsent, bule->lifetime, bule->expires);
	else if (bule->type == NON_MIP_CN_ENTRY) {
		bule->expires = bule->lastsent;
	} else {
		/* Deregistration entry, expires after 10000 seconds...*/
		tsadd(DEREG_BU_LIFETIME_TS, bule->lastsent, bule->expires);
	}
}

/* Adds bul entry to both hashes and adds a timer for expiry / resend. 
   Caller must fill all non-private fields of bule */
int bul_add(struct bulentry *bule)
{
	int ret = 0;
	struct timespec timer_expire;
	assert(bule && tsisset(bule->lifetime));
	
	BDBG("******* [%p] *******\n", bule);

	if ((ret = hash_add(&bul_hash, bule, &bule->hoa, &bule->peer_addr)) < 0)
		return ret;

	clock_gettime(CLOCK_REALTIME, &bule->lastsent);
	if (bule->type == BUL_ENTRY) {
		assert(&bule->home != NULL);
		if ((ret = hash_add(&bule->home->bul,
				    bule, NULL, &bule->peer_addr)) < 0)
			goto bul_free;
		if ((ret = xfrm_pre_bu_add_bule(bule)) < 0)
			goto home_bul_free;
	} else if (bule->type == HOT_ENTRY) {
		assert(bule->home != NULL);
		if ((ret = hash_add(&bule->home->bul, 
				    bule, NULL, &bule->peer_addr)) < 0)
			goto bul_free;
	} else if (bule->type == NON_MIP_CN_ENTRY) {
		assert(bule->home != NULL);
		if ((ret = hash_add(&bule->home->bul, 
				    bule, NULL, &bule->peer_addr)) < 0)
			goto bul_free;
		if (bule->flags & IP6_MH_BU_HOME && xfrm_block_hoa(bule->home) < 0)
			goto home_bul_free;

	}
	tsadd(bule->delay, bule->lastsent, timer_expire);
	add_task_abs(&timer_expire, &bule->tqe, bule->callback);
	return 0;
home_bul_free:
	hash_delete(&bule->home->bul, &bule->hoa, &bule->peer_addr);
bul_free:
	hash_delete(&bul_hash, &bule->hoa, &bule->peer_addr);
	return ret; 
}
void bul_cleanup_cote(struct bulentry *bule)
{
	struct list_head *list, *n;
	BDBG("Deleting entries from COT entry home address list\n");
	list_for_each_safe(list, n, &bule->rr.home_addrs) {
		list_del(list);
		free(list_entry(list, struct addr_holder, list));
	}
}

/* bul_delete - deletes a bul entry */
void bul_delete(struct bulentry *bule)
{
	assert(bule);

	BDBG("******* [%p] *******\n", bule);

	hash_delete(&bul_hash, &bule->hoa, &bule->peer_addr);
	del_task(&bule->tqe);
	if (bule->type == COT_ENTRY) {
		bul_cleanup_cote(bule);
	} else { 
		if (bule->type != NON_MIP_CN_ENTRY)
			xfrm_del_bule(bule);
		else if (bule->flags & IP6_MH_BU_HOME)
			xfrm_unblock_hoa(bule->home);
		hash_delete(&bule->home->bul, NULL, &bule->peer_addr);
	}
	while (bule->ext_cleanup)
		bule->ext_cleanup(bule);
	free_bule(bule);
}

/* bul_init - initializes global bul */
int bul_init(void)
{
	int ret;

	ret = hash_init(&bul_hash, DOUBLE_ADDR, BUL_BUCKETS);

#ifdef ENABLE_VT
	if (ret < 0)
		return ret;

	ret = vt_bul_init();
#endif

	return ret;
}

/* bul_home_init - initializes a bul */
int bul_home_init(struct home_addr_info *home)
{
	return hash_init(&home->bul, SINGLE_ADDR, BUL_BUCKETS);
}

/* bule_cleanup - cleans up a bulentry */
static int bule_cleanup(void *vbule, void *vbul)
{
	struct bulentry *bule = vbule;
	struct hash *bul = vbul;
	BDBG("\n");
	if (bul)
		hash_delete(bul, &bule->hoa, &bule->peer_addr);
	hash_delete(&bul_hash, &bule->hoa, &bule->peer_addr);
	del_task(&bule->tqe);
	if (bule->ext_cleanup)
		bule->ext_cleanup(bule);
	if (bule->type == COT_ENTRY)
		bul_cleanup_cote(bule);
	else if (bule->type != NON_MIP_CN_ENTRY) 
		xfrm_del_bule(bule);
	free_bule(bule);
	return 0;
}

/* bul_home_cleanup - cleans up a bul 
 * @bul: binding update list to clean up
 */
void bul_home_cleanup(struct hash *bul)
{
	hash_iterate(bul, bule_cleanup, bul);	
	hash_cleanup(bul);
}

void bul_flush(void)
{
	hash_iterate(&bul_hash, bule_cleanup, NULL);	
}

/* bul_cleanup - cleans up global bul */
void bul_cleanup(void)
{
	hash_cleanup(&bul_hash);
}

/* bul_iterate - iterates through binding update list calling func for
 * every entry. 
 * @func: function to be called for every entry, @func
 * takes a void cast bulentry as its first argument and @arg as its
 * second.  
 * @arg: second argument with which @func is called for every
 * bul entry 
 */
int bul_iterate(struct hash *h, int (* func)(void *, void *), void *arg)
{
	struct hash *tmp = h ? h : &bul_hash;
	return hash_iterate(tmp, func, arg);
}
