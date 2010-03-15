#ifndef __HOA4_H__
#define __HOA4_H__ 1

#include <netinet/in.h>
#include <stdio.h>

#include "utils.h"
#include "conf.h"

struct hoa4_mnp4 {
	struct in_addr hoa4;
	struct net_prefix4 *mob_net_prefixes4;
	int mnp4_count;
	char hoa4_enabled_by_MR;
	struct hoa4_mnp4 *next;
};

static inline char is_hoa4enabled(struct in_addr *addr4)
{
	if (addr4 == NULL) return 0;
	struct hoa4_mnp4 *current = conf.mnpv4;
	while (current != NULL) {
		if(ip_equal(&current->hoa4, addr4))
			return current->hoa4_enabled_by_MR;
		current = current->next;
	}
	return 0;
}
char set_hoa4enabled(struct in_addr *addr, char hoa4enabled);

#endif
