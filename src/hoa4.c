/* hoa4.c
 * HoA4-retated utility functions
 *
 * Original authors:
 * 	Duc Kien NGUYEN <kien.duc-nguyen@univ-paris8.fr>
 *	Nassim KOBEISSY <nassim.kobeissy@gmail.com>
 */
#include "hoa4.h"

char set_hoa4enabled(struct in_addr *addr4, char hoa4enabled)
{
	if (addr4 == NULL) return 0;
	struct hoa4_mnp4 *current = conf.mnpv4;
	while (current != NULL) {
		if (ip_equal(&current->hoa4, addr4)) {
			current->hoa4_enabled_by_MR = hoa4enabled;
			return 1;
		}
		current = current->next;
	}
	return 0;
}

