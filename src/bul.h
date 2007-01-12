/* $Id: bul.h 1.55 05/12/10 03:59:28+02:00 vnuorval@tcs.hut.fi $ */

#ifndef __BUL_H__
#define __BUL_H__ 1

#include <netinet/in.h>

#include "mipv6.h"
#include "tqueue.h"
#include "hash.h"
#include "list.h"

struct home_addr_info;

struct retrout_info {
	struct timespec kgen_expires;
	uint8_t cookie[8];
	uint8_t kgen_token[8];
	int dereg; /* for calculating BSA key */
	uint8_t wait_hot; /* WAIT / READY */
	uint8_t wait_cot; /* WAIT / READY */
	uint8_t do_send_bu; /* send bu / not send bu */
	uint16_t coa_nonce_ind;
	uint16_t home_nonce_ind;
	struct list_head home_addrs; /* List of HoAs for CoT entry */
};

struct addr_holder {
	struct list_head list;
	struct in6_addr addr;
};

struct bulentry {
	struct home_addr_info *home;    /* Pointer to home_address structure */
					/* to which this entry belongs to */
	struct tq_elem tqe;             /* Timer queue entry */
	struct in6_addr peer_addr;      /* CN / HA address */
	struct in6_addr hoa;
	struct in6_addr coa;		/* care-of address of the sent BU */
	int if_coa;
	struct in6_addr prev_coa;        /* Previous coa */      
	struct timespec lastsent;

	struct timespec lifetime;      	/* lifetime sent in this BU in seconds*/
	struct timespec expires;        /* In seconds */
	uint16_t seq;			/* sequence number of the latest BU */
	uint16_t flags;			/* BU send flags */
	uint8_t wait_ack;      		/* WAIT / READY */
	struct timespec delay;		/* call back time in ms*/
	int consecutive_resends;	/* Number of consecutive BU's sent */

	int xfrm_state;
	int use_alt_coa;               /* Whether to use alt. CoA option */
	int coa_changed;
	
	void (* callback)(struct tq_elem *);
	void (*ext_cleanup)(struct bulentry *);

	/* Information for return routability */
	struct retrout_info rr;

	uint8_t bind_key[HMAC_SHA1_KEY_SIZE];
	int type; /* BUL entry / COT entry */
};

/* Types for bulentry */
enum {
	COT_ENTRY,
	HOT_ENTRY,
	BUL_ENTRY,
	NON_MIP_CN_ENTRY
};

/* Types of xfrm_states */
#define BUL_XFRM_STATE_SIG 0x1
#define BUL_XFRM_STATE_DATA 0x2

struct bulentry *bul_get(struct home_addr_info *hinfo,
			 const struct in6_addr *our_addr,
			 const struct in6_addr *peer_addr);

int bul_add(struct bulentry *bule);

void bul_update(struct bulentry *bule);
void bul_delete(struct bulentry *bule);
void bul_update_timer(struct bulentry *bule);
void bul_update_expire(struct bulentry *bule);

int bul_iterate(struct hash *h, int (* func)(void *bule, void *arg), void *arg);

int bul_init(void);
int bul_home_init(struct home_addr_info *home);
void bul_home_cleanup(struct hash *bul);
void bul_flush(void);
void bul_cleanup(void);
void dump_bule(struct bulentry *bule);
struct bulentry *create_bule(struct in6_addr *cn_addr);
void free_bule(struct bulentry *bule);

#endif
