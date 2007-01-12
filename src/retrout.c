/*
 * $Id: retrout.c 1.110 05/12/10 03:59:28+02:00 vnuorval@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 * 
 * Authors:
 *  Henrik Petander <petander@tcs.hut.fi>
 *  Antti Tuominen <anttit@tcs.hut.fi>
 *
 * Copyright 2003-2005 GO-Core Project
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
#include <syslog.h>
#include <time.h>
#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#else
#error "POSIX Thread Library required!"
#endif
#include <netinet/in.h>
#include <netinet-ip6mh.h>
#include <openssl/rand.h>

#include "debug.h"
#include "mipv6.h"
#include "util.h"
#include "bul.h"
#include "mh.h"
#include "xfrm.h"
#include "mn.h"
#include "keygen.h"

#define RR_DEBUG_LEVEL 1

#if RR_DEBUG_LEVEL >= 1
#define RRDBG dbg
#else 
#define RRDBG(...) 
#endif /* RRDBG */

const struct timespec mn_test_init_delay_ts = { MN_TEST_INIT_DELAY, 0 };
#define MN_TEST_INIT_DELAY_TS mn_test_init_delay_ts

static inline int cookiecmp(const uint8_t *cookie_a, const uint8_t *cookie_b)
{
	return memcmp(cookie_a, cookie_b, 8);
}

static void mn_send_hoti(struct bulentry *bule, int oif)
{
	struct iovec iov;
	struct ip6_mh_home_test_init *hti;
	struct in6_addr_bundle out;

	out.src = &bule->hoa;
	out.dst = &bule->peer_addr;
	out.local_coa = NULL;
	out.remote_coa = NULL;

	hti = mh_create(&iov, IP6_MH_TYPE_HOTI);
	if (!hti)
		return;

	RAND_pseudo_bytes((uint8_t *)hti->ip6mhhti_cookie, 8);
	cookiecpy(bule->rr.cookie, hti->ip6mhhti_cookie);

	mh_send(&out, &iov, 1, NULL, oif);
	free(iov.iov_base);
}

static void mn_send_coti(struct bulentry *bule, int oif)
{
	struct iovec iov;
	struct ip6_mh_careof_test_init *cti;
	struct in6_addr_bundle out;

	out.src = &bule->coa;
	out.dst = &bule->peer_addr;
	out.local_coa = NULL;
	out.remote_coa = NULL;

	cti = mh_create(&iov, IP6_MH_TYPE_COTI);
	if (!cti)
		return;

	RAND_pseudo_bytes((uint8_t *)cti->ip6mhcti_cookie, 8);
	cookiecpy(bule->rr.cookie, cti->ip6mhcti_cookie);
	/*
	 * Record information in the Binding Update List:
	 * - source address (careof)
	 * - destination address (cn)
	 * - send time
	 * - cookie (hti->mhcti_cookie)
	 */

	mh_send(&out, &iov, 1, NULL, oif);
	free(iov.iov_base);
}

/* Resend HoTi or CoTi, if we haven't got HoT or CoT */ 
static void ti_resend(struct tq_elem *tqe)
{
	struct timespec now;
	struct bulentry *bule;
	struct bulentry *home_bule = NULL;
	struct list_head *list, *n;

	pthread_rwlock_wrlock(&mn_lock);

	if (task_interrupted()) {
		pthread_rwlock_unlock(&mn_lock);
		return;
	}
	bule = tq_data(tqe, struct bulentry, tqe);

	clock_gettime(CLOCK_REALTIME, &now);
	if (bule->type == COT_ENTRY) {
		list_for_each_safe(list, n, &bule->rr.home_addrs) {
			struct addr_holder *ah;
			ah = list_entry(list, struct addr_holder, list);

			home_bule = bul_get(NULL, &ah->addr, &bule->peer_addr);

			if (home_bule == NULL)
				goto out;

			if (!IN6_ARE_ADDR_EQUAL(&bule->coa, &home_bule->coa)) {
				/* TODO: If some of the home addresses
				 * still use the CoA, this works
				 * incorrectly */
				goto out;
			}
			if (tsisset(home_bule->expires) &&
			    tsafter(home_bule->expires, now))
				goto out;
		}

		bule->rr.wait_cot = 1;

		mn_send_coti(bule, bule->if_coa);
	} else if (bule->type == HOT_ENTRY) { 
		if (tsisset(bule->expires) && tsafter(bule->expires, now))
			goto out;

		mn_send_hoti(bule, bule->home->hoa.iif);
	}

	tsadd(bule->delay, bule->delay, bule->delay); /* 2 * bule->delay */
	bule->delay = tsmin(bule->delay, MAX_BINDACK_TIMEOUT_TS);
	bule->lastsent = now;

	bul_update_timer(bule);

	pthread_rwlock_unlock(&mn_lock);

	return;

 out:
	bul_delete(bule);
	pthread_rwlock_unlock(&mn_lock);
}

static inline void set_refresh(struct timespec *delay, 
			       const struct timespec *exp,
			       const struct timespec *lft)
{
	struct timespec rlft;

	tssetsec(rlft, lft->tv_sec * BU_REFRESH_DELAY);
	tssub(*exp, *lft, *delay);
	tsadd(*delay, rlft, *delay);
}

/* Renew HoTi before HoT key gen. token expires to optimize handoff
 * performance, if kernel bule has been recently used
 */
void mn_rr_check_entry(struct tq_elem *tqe)
{
	struct bulentry *bule;
	struct bulentry *bule_cot = NULL;
	struct timespec now, refresh_delay;
	long last_used;
	
	pthread_rwlock_wrlock(&mn_lock);

	if (task_interrupted()) {
		pthread_rwlock_unlock(&mn_lock);
		return;
	}
	bule = tq_data(tqe, struct bulentry, tqe);

	clock_gettime(CLOCK_REALTIME, &now);

	last_used = xfrm_last_used(&bule->peer_addr, &bule->hoa,
				   IPPROTO_DSTOPTS, &now);

	set_refresh(&refresh_delay, &bule->expires, &bule->lifetime);

	if (last_used >= 0 && last_used < MN_RO_RESTART_THRESHOLD) {
		struct timespec kgen_refresh_delay;

		set_refresh(&kgen_refresh_delay, &bule->rr.kgen_expires,
			    &MAX_TOKEN_LIFETIME_TS);
		RRDBG("now                %d\n", now.tv_sec);
		RRDBG("kgen_refresh_delay %d\n", kgen_refresh_delay.tv_sec);
		RRDBG("refresh_delay      %d\n", refresh_delay.tv_sec);

		if (tsafter(kgen_refresh_delay, now)) {
			RRDBG("renewing HoTi\n");
			bule->lastsent = now;
			bule->type = HOT_ENTRY;
			bule->callback = ti_resend; 
			bule->lifetime = MAX_RR_BINDING_LIFETIME_TS;
			/* XXX: original retransmit interval is too short */
			bule->delay = MN_TEST_INIT_DELAY_TS;
			bule->rr.wait_hot = 1;
			if (tsafter(refresh_delay, now))
				bule->rr.do_send_bu = 1;
			else
				bule->rr.do_send_bu = 0;
			mn_send_hoti(bule, bule->home->hoa.iif);
			bul_update_timer(bule);

		} else if (tsafter(refresh_delay, now)) {
			bule_cot = bul_get(NULL, &bule->coa, &bule->peer_addr);
			if (bule_cot == NULL) {
				BUG("no COT bulentry");
				pthread_rwlock_unlock(&mn_lock);
				return;
			
			} else if (bule_cot && bule_cot->rr.wait_cot) {
				/* Wait for CoT */
				bule->delay = MN_TEST_INIT_DELAY_TS;
				bule->lifetime = MAX_RR_BINDING_LIFETIME_TS;
				bul_update_timer(bule);
				pthread_rwlock_unlock(&mn_lock);
				return;
				/* Foreign Reg BU case */
			} else if (bule_cot && !bule_cot->rr.wait_cot) {
				bule->rr.coa_nonce_ind = bule_cot->rr.coa_nonce_ind;
				rr_mn_calc_Kbm(bule->rr.kgen_token,
					       bule_cot->rr.kgen_token, 
					       bule->bind_key);
			
				mn_send_cn_bu(bule);
			}
		}
	} else {
		RRDBG("now           %d\n", now.tv_sec);
		RRDBG("refresh_delay %d\n", refresh_delay.tv_sec);
		if (tsbefore(refresh_delay, now)) {
			/* enough lifetime left, don't delete bule */
			bule->type = BUL_ENTRY;
			tssub(bule->expires, bule->lifetime, bule->lastsent);
			tssub(refresh_delay, bule->lastsent, bule->delay);
			bule->callback = mn_rr_check_entry; 
			RRDBG("expires       %d\n", bule->expires.tv_sec);
			RRDBG("lastsent      %d\n", bule->lastsent.tv_sec);
			RRDBG("refresh_delay %d\n", refresh_delay.tv_sec);
			RRDBG("delay         %d\n", bule->delay.tv_sec);
			bul_update_timer(bule);
		} else {
			RRDBG("deleting unused binding\n");
			bule_cot = bul_get(NULL, &bule->coa, &bule->peer_addr);
			if (bule_cot != NULL) 
				bul_delete(bule_cot);

			bul_delete(bule);
		}
	}
	pthread_rwlock_unlock(&mn_lock);
}

static int add_hoa_to_bule(struct bulentry *bule, struct in6_addr *addr)
{
	struct list_head *list;
	struct addr_holder *addr_c;

	list_for_each(list, &bule->rr.home_addrs) {
		addr_c = list_entry(list, struct addr_holder, list);
		if (IN6_ARE_ADDR_EQUAL(addr, &addr_c->addr)) 
			return 1;
	}
	addr_c = malloc(sizeof(*addr_c));
	if (!addr_c) 
		return -1;
	addr_c->addr = *addr;
	list_add(&addr_c->list, &bule->rr.home_addrs);

	return 0;
}

static struct bulentry *create_cot_bule(struct in6_addr *coa, int coa_if,
					struct in6_addr *cn_addr, 
					struct in6_addr *home)
{
	struct bulentry *bule = create_bule(NULL);

	if (!bule) {
		RRDBG("Malloc failed in create_cot_bule\n");
		return NULL;
	}
	bule->hoa = *coa;
	bule->peer_addr = *cn_addr;

	/* XXX: original retransmit interval is too short */
	bule->delay = MN_TEST_INIT_DELAY_TS;
	bule->lifetime = MAX_TOKEN_LIFETIME_TS;
	bule->callback = ti_resend;
	bule->coa = *coa;
	bule->if_coa = coa_if;
	bule->type = COT_ENTRY;

	if (add_hoa_to_bule(bule, home) < 0 || bul_add(bule) < 0) {
		free(bule);
		return NULL;
	}
	return bule;
}

/* Checks if COT/HOT token is valid  */
static inline int mn_rr_token_valid(struct bulentry *bule)
{
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);
	if (tsbefore(bule->rr.kgen_expires, now))
		return 1;

	return 0;
}

/** 
 * mn_rr_cond_start_hot - send HoTi, if it is necessary
 * v_bule: bul entry for RO binding created in start_ro  
 * uncond: set this to override all freshness checks and send HoTi in any case
 */
int mn_rr_cond_start_hot(void *vbule, int uncond)
{
	struct bulentry *bule = vbule;
	struct timespec now;

	if (bule->type != BUL_ENTRY)
		return 1;

	if (!uncond && mn_rr_token_valid(bule)) {
		RRDBG("RR key gen token valid for HoT entry\n");
		return 0;
	}

	RRDBG("RR key gen token not valid for HoT entry\n");

	clock_gettime(CLOCK_REALTIME, &now);	
	bule->type = HOT_ENTRY;
	bule->callback = ti_resend; 
	bule->lastsent = now;
	bule->lifetime = MAX_RR_BINDING_LIFETIME_TS;
	bule->delay = MN_TEST_INIT_DELAY_TS;
	tsclear(bule->rr.kgen_expires);
	bule->rr.wait_hot = 1;
	bule->rr.do_send_bu = 1;
	mn_send_hoti(bule, bule->home->hoa.iif);
	bul_update_timer(bule);

	return 1;
}

/**
 * mn_rr_post_home_handoff - finalize RO after handoff
 * @vbule: bulentry for CN
 * @vhbule: bulentry from which CoA is taken
 *
 * Sends HoTi after tunnel with HA is ready or 
 * dereg BU to CN after getting dereg BA from HA.
 **/
int mn_rr_post_home_handoff(void *vbule, void *vdereg)
{
	struct bulentry *bule = vbule;
	int dereg = *(int*) vdereg; 

	if (vbule == NULL)
		return -1;

	if ((bule->flags & IP6_MH_BU_HOME))
		return 0;

	/* Is HoT kgen token is still valid ? */
	if (mn_rr_cond_start_hot(bule, 0))
		return 0;

	if (dereg) {
		RRDBG("Returning home, no need for CoT cookie\n");
		bule->coa = bule->hoa;
		tsclear(bule->lifetime);
		rr_mn_calc_Kbm(bule->rr.kgen_token, NULL, bule->bind_key);
		bule->rr.dereg = 1;
		mn_send_cn_bu(bule);
	}

	return 0;
}

/**
 * mn_rr_cond_start_cot - send Coti, if necessary 
 * @bule: RO bul entry
 * @co_bule_p: pointer to CoT bulentry or NULL
 * @coa: Care-of address for CoT
 * @ifindex: interface index for CoA
 * @uncond: send CoT even if current kgen token is fresh
 *
 * Function manages sending of CoTi in a handoff and also changes the
 * CoA in RO bul entry.
 **/
int mn_rr_cond_start_cot(struct bulentry *bule, struct bulentry **co_bule_p, 
			 struct in6_addr *coa, int ifindex, int uncond)
{
	struct timespec now;
	struct bulentry *co_bule = NULL;

	if (co_bule_p != NULL && *co_bule_p != NULL)
		co_bule = *co_bule_p;
	
	if (bule->type != BUL_ENTRY && (bule->flags & IP6_MH_BU_HOME)){
		RRDBG("Not starting Care of test with HA\n");
		return 0;
	}

	if (co_bule == NULL) {
		co_bule = bul_get(NULL, coa, &bule->peer_addr);
		if (co_bule == NULL) {
			co_bule = create_cot_bule(coa, ifindex,
						  &bule->peer_addr, 
						  &bule->hoa);
			if (co_bule == NULL) {
				RRDBG("Failed to create new CoT bulentry\n");
				return -1;
			}
			RRDBG("Created new CoT bulentry for CoA\n");
		} else {
			if (add_hoa_to_bule(co_bule, &bule->hoa) < 0)
				RRDBG("Failed to add HoA to CoT bule\n");
		}
	}
	bule->coa = *coa;
	bule->if_coa = ifindex;

	if (!uncond && mn_rr_token_valid(co_bule)){
		RRDBG("No need to send CoTi\n");
		if (co_bule_p)
			*co_bule_p = co_bule;
		return 0;
	}
	if (co_bule->rr.wait_cot) {
		RRDBG("CoTi already sent\n");
		return 0;
	}

	co_bule->rr.wait_cot = 1;
	bule->rr.do_send_bu = 1;
	clock_gettime(CLOCK_REALTIME, &now);	
	co_bule->lastsent = now;
	co_bule->lifetime = MAX_RR_BINDING_LIFETIME_TS;
	co_bule->delay = MN_TEST_INIT_DELAY_TS;
	/* Invalidate cookie */
	co_bule->rr.kgen_expires = now;
	RRDBG("Sending CoTi\n"); 
	mn_send_coti(co_bule, co_bule->if_coa);
	bul_update_timer(co_bule);

	return 1;
}

/**
 * mn_rr_start_handoff - start RR procedure after changing CoA
 * vbule: RO bulentry
 * vcoa: New care-of address
 * 
 * Function sends CoTi to CN, if MN doesn't have a fresh CoT key
 * gen. token. If MN has a fresh CoT & HoT key gen. token, function
 * sends a BU to CN.
 **/
int mn_rr_start_handoff(void *vbule, void *vcoa)
{
	struct bulentry *bule = vbule;
	struct mn_addr *coa = vcoa;
	struct bulentry *co_bule = NULL;

	if (vbule == NULL) return -1;

	switch (bule->type) {
	case COT_ENTRY:
	case HOT_ENTRY:
		RRDBG("HoT/CoT entry\n");	
		break;
	case NON_MIP_CN_ENTRY:
		RRDBG("Non-MIP6 entry\n");
		/* flush Non-MIP6 entries when returning home */
		if (bule->home->at_home) 
			bul_delete(bule);
		break;
	case BUL_ENTRY:
		if ((bule->flags & IP6_MH_BU_HOME)) {
			RRDBG("Home entry\n");
			break;
		}

		/* mn_rr_cond_start_cot() may set co_bule */
		if (mn_rr_cond_start_cot(bule, &co_bule, &coa->addr, coa->iif, 0)) {
			RRDBG("Started RR test for CoTi\n");
			break;
		}

		RRDBG("RR test not necessary for CoTi\n");
		if (!co_bule) {
			BUG("co_bule ptr not set");
			break;
		}

		if (mn_rr_token_valid(bule)) {
			rr_mn_calc_Kbm(bule->rr.kgen_token, 
				       co_bule->rr.kgen_token, bule->bind_key);
			mn_send_cn_bu(bule);
		}
		break;
	default:
		/* should not be reachable */
		break;
	}

	return 0;	
}


/* mn_start_ro - start RO, triggered by tunneled packet */
void mn_start_ro(struct in6_addr *cn_addr, struct in6_addr *home_addr,
		 struct mn_addr *coa)
{
	struct bulentry *bule_ro;
	
	RRDBG("MN: Start RO to %x:%x:%x:%x:%x:%x:%x:%x, "
	      "from %x:%x:%x:%x:%x:%x:%x:%x\n", 
	      NIP6ADDR(cn_addr), NIP6ADDR(home_addr));
	
	pthread_rwlock_wrlock(&mn_lock);

	/* First look up bulentry for CN */
	bule_ro = bul_get(NULL, home_addr, cn_addr);

	/* See, if RR is already in progress for HoA and CoA (ie
	 * bulentry for HoT exists). If no bulentry exists create one
	 * for HoT */
	if (bule_ro) {
		/* This whole branch is just for debugging */
		if (bule_ro->flags & IP6_MH_BU_HOME) {
			/* HA communicates with us through the tunnel
			 * for some reason */
			RRDBG("HA triggered RO by sending packets through tunnel ?\n");
		} else if (bule_ro->type == COT_ENTRY) {
			/* We already are using the home address as
			 * CoA with CN ?? */
			RRDBG("Looping RO coa <-> hoa ??\n");
		} else if (bule_ro->type == HOT_ENTRY) {
			RRDBG("Already doing RR, bailing out\n");
		} else if (bule_ro->type == BUL_ENTRY) {
			RRDBG("Valid BUL entry for CN, no RR necessary\n");
		} else if (bule_ro->type == NON_MIP_CN_ENTRY) {
			RRDBG("Not starting RO with non-mipv6 capable CN\n");
		} 

		pthread_rwlock_unlock(&mn_lock);
		return;
	} 

	struct home_addr_info *hai = mn_get_home_addr(home_addr);
	if (!hai) {
		RRDBG("Failed to find home address info for starting of RO\n");
		pthread_rwlock_unlock(&mn_lock);
		return;
	}
	bule_ro = create_bule(NULL);
	if (!bule_ro) {
		RRDBG("Malloc failed at starting of RO\n");
		pthread_rwlock_unlock(&mn_lock);
		return;
	}
	bule_ro->hoa = *home_addr;
	bule_ro->peer_addr = *cn_addr;
	bule_ro->callback = ti_resend;
	bule_ro->lifetime = MAX_TOKEN_LIFETIME_TS;
	bule_ro->delay = MN_TEST_INIT_DELAY_TS;
	bule_ro->coa = coa->addr;
	bule_ro->if_coa = coa->iif;
	bule_ro->type = HOT_ENTRY;
	bule_ro->rr.wait_hot = 1;
	bule_ro->home = hai;
	if (bul_add(bule_ro) < 0) {
		free(bule_ro);
		pthread_rwlock_unlock(&mn_lock);
		return;
	}
	bule_ro->rr.do_send_bu = 1;
	mn_send_hoti(bule_ro, bule_ro->home->hoa.iif);

	RRDBG("Started RO & sent HoTi\n");

	/* See if we already have a bulentry for CoT */
	if (mn_rr_cond_start_cot(bule_ro, NULL, &coa->addr, coa->iif, 0)) {
		RRDBG("Started RR test for CoA\n");
	} else {
		RRDBG("RR test not necessary for CoA\n");
	} 

	pthread_rwlock_unlock(&mn_lock);
}

static void mn_recv_cot(const struct ip6_mh *mh,
			const ssize_t len,
			const struct in6_addr_bundle *in,
			const int iif)
{
	struct in6_addr *cn_addr = in->src;
	struct in6_addr *co_addr = in->dst;
	uint8_t *cookie;
	uint8_t *keygen;
	uint16_t index;
	struct bulentry *bule_home; /* Real bule for HoT / RR entry for CoT */ 
	struct bulentry *bule_cot; /* RR entry for HoT / real one for CoT */
	struct ip6_mh_careof_test *ct;
	struct list_head *list, *n;
	struct timespec now,refresh_delay;

	if (len < sizeof(struct ip6_mh_careof_test) || in->remote_coa)
		return;

	ct = (struct ip6_mh_careof_test *)mh;
	cookie = (uint8_t *)ct->ip6mhct_cookie;
	keygen = (uint8_t *)ct->ip6mhct_keygen;
	index = ntohs(ct->ip6mhct_nonce_index);

	pthread_rwlock_wrlock(&mn_lock);
	bule_cot = bul_get(NULL, co_addr, cn_addr);

	if (bule_cot == NULL || cookiecmp(bule_cot->rr.cookie, cookie)) {
		RRDBG("Got CoT, but no corresponding bulentry\n");
		pthread_rwlock_unlock(&mn_lock);
		return;
	}

	if (!bule_cot->rr.wait_cot) {
		RRDBG("Got unexpected CoT\n");
		pthread_rwlock_unlock(&mn_lock);
		return;
	}

	bule_cot->rr.wait_cot = 0;
	bule_cot->rr.coa_nonce_ind = index;
	memcpy(bule_cot->rr.kgen_token, keygen, sizeof(bule_cot->rr.kgen_token));
	/* Send BU to CN for every home address waiting for the CoT */
	clock_gettime(CLOCK_REALTIME, &now);
	list_for_each_safe(list, n, &bule_cot->rr.home_addrs) {
		struct addr_holder *ah;

		ah = list_entry(list, struct addr_holder, list);
		bule_home = bul_get(NULL, &ah->addr, cn_addr);

		if (bule_home == NULL) {
			RRDBG("No bule for home address in list, deleting entry\n");
			list_del(list);
			free(ah);
			continue;
		}

		RRDBG("Got CoT and found bulentry for home address \n");

		if (bule_home->rr.wait_hot) {
			RRDBG("Still waiting for HoT, not sending BU\n");
			continue;
		}

		set_refresh(&refresh_delay, &bule_home->expires, 
			    &bule_home->lifetime);

		RRDBG("refresh_delay %d\n", refresh_delay.tv_sec);
		RRDBG("now           %d\n", now.tv_sec);
		RRDBG("expires       %d\n", bule_home->expires.tv_sec);

		if (bule_home->rr.do_send_bu || tsafter(refresh_delay, now)) {
			bule_home->coa = *co_addr;
			rr_mn_calc_Kbm(bule_home->rr.kgen_token, keygen,
				       bule_home->bind_key);
			bule_home->rr.coa_nonce_ind = index;
			bule_home->type = BUL_ENTRY;
			mn_send_cn_bu(bule_home);
		}
	}
	tssetsec(bule_cot->delay, MAX_TOKEN_LIFETIME - MN_RR_BEFORE_EXPIRE);
	bule_cot->lastsent = now;
	tsadd(MAX_TOKEN_LIFETIME_TS, bule_cot->lastsent, 
	      bule_cot->rr.kgen_expires);

	bul_update_timer(bule_cot);
	pthread_rwlock_unlock(&mn_lock);
}

static struct mh_handler mn_cot_handler = {
	.recv = mn_recv_cot,
};

/* mh_hot_recv - handles MH HoT msg */
static void mn_recv_hot(const struct ip6_mh *mh,
			const ssize_t len,
			const struct in6_addr_bundle *in,
			const int iif)
{
	struct in6_addr *cn_addr = in->src;
	struct in6_addr *home_addr = in->dst;
	uint8_t *cookie;
	uint16_t index;
	struct bulentry *bule_home; /* Real bule for HoT / RR entry for CoT */ 
	struct bulentry *bule_cot = NULL; /* RR entry for HoT / real for CoT */
	struct ip6_mh_home_test *ht;
	struct timespec now, tmp, refresh_delay;

	if (len < sizeof(struct ip6_mh_home_test) || in->remote_coa)
		return;

	ht = (struct ip6_mh_home_test *)mh;
	cookie = (uint8_t *)ht->ip6mhht_cookie;
	index = ntohs(ht->ip6mhht_nonce_index);

	pthread_rwlock_wrlock(&mn_lock);

	bule_home = bul_get(NULL, home_addr, cn_addr);

	if (bule_home == NULL || cookiecmp(bule_home->rr.cookie, cookie)) {
		RRDBG("Got HoT, but no corresponding bulentry\n");
		pthread_rwlock_unlock(&mn_lock);
		
		return;
	}

	if (bule_home->type == NON_MIP_CN_ENTRY || !bule_home->rr.wait_hot) {
		RRDBG("Got unexpected HoT\n");
		pthread_rwlock_unlock(&mn_lock);
		
		return;
	}  
	
	bule_home->rr.wait_hot = 0;
	clock_gettime(CLOCK_REALTIME, &now);	
	tssub(now, bule_home->lastsent, tmp);

	bule_home->lastsent = now;
	tsadd(bule_home->lastsent, MAX_TOKEN_LIFETIME_TS,
	      bule_home->rr.kgen_expires);
	bule_home->rr.home_nonce_ind = index;
	memcpy(bule_home->rr.kgen_token, ht->ip6mhht_keygen,
	       sizeof(bule_home->rr.kgen_token));

	bule_cot = bul_get(NULL, &bule_home->coa, cn_addr);

	if (bule_cot == NULL) {
		if (bule_home->rr.dereg) {
			rr_mn_calc_Kbm(bule_home->rr.kgen_token, NULL, 
				       bule_home->bind_key);
			goto out;
		} else {
			BUG("no COT bulentry");
			pthread_rwlock_unlock(&mn_lock);
			return;
		}
	}

	if (bule_cot->rr.wait_cot) {
		/* Wait for CoT */
		tssub(bule_home->rr.kgen_expires, now, bule_home->delay);
		bule_home->lifetime = MAX_RR_BINDING_LIFETIME_TS;
		bul_update_timer(bule_home);
		pthread_rwlock_unlock(&mn_lock);

		return;
	}

	/* Foreign Reg BU case */
	bule_home->rr.coa_nonce_ind = bule_cot->rr.coa_nonce_ind;
	rr_mn_calc_Kbm(bule_home->rr.kgen_token, bule_cot->rr.kgen_token, 
		       bule_home->bind_key);

	set_refresh(&refresh_delay, &bule_home->expires, &bule_home->lifetime);

	if (!bule_home->rr.do_send_bu && tsbefore(refresh_delay, now)) {
		struct timespec rr_lifetime;

		bule_home->type = BUL_ENTRY;
		tssub(bule_home->expires, bule_home->lifetime, 
		      bule_home->lastsent);
		tssub(bule_home->rr.kgen_expires, bule_home->lastsent,
		      rr_lifetime);

		if (tsbefore(refresh_delay, bule_home->rr.kgen_expires))
			tssetsec(bule_home->delay, 
				 max(rr_lifetime.tv_sec - 
				     MN_RR_BEFORE_EXPIRE, 0));
		else
			tssub(refresh_delay, bule_home->lastsent, 
			      bule_home->delay);

		bule_home->callback = mn_rr_check_entry; 

		RRDBG("delay         %d\n", bule_home->delay.tv_sec);
		RRDBG("refresh_delay %d\n", refresh_delay.tv_sec);
		RRDBG("kgen_expires  %d\n", bule_home->rr.kgen_expires.tv_sec);
		RRDBG("lifetime      %d\n", bule_home->lifetime.tv_sec);
		RRDBG("expires       %d\n", bule_home->expires.tv_sec);
		RRDBG("lastsent      %d\n", bule_home->lastsent.tv_sec);
		RRDBG("now           %d\n", now.tv_sec);

		bul_update_timer(bule_home);
		pthread_rwlock_unlock(&mn_lock);

		return;
}

 out:
	bule_home->type = BUL_ENTRY;
	mn_send_cn_bu(bule_home);
	pthread_rwlock_unlock(&mn_lock);
}

static struct mh_handler mn_hot_handler = {
	.recv = mn_recv_hot,
};

void rr_init(void)
{
	mh_handler_reg(IP6_MH_TYPE_COT, &mn_cot_handler);
	mh_handler_reg(IP6_MH_TYPE_HOT, &mn_hot_handler);
}

void rr_cleanup(void)
{
	mh_handler_dereg(IP6_MH_TYPE_HOT, &mn_hot_handler);
	mh_handler_dereg(IP6_MH_TYPE_COT, &mn_cot_handler);
}
