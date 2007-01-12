/* $Id: libmip6.h 1.1 04/07/11 15:11:39+03:00 anttit@tcs.hut.fi $ */

#ifndef __LIBMIP6_H__
#define __LIBMIP6_H__ 1

#include <netinet/in.h>

typedef struct mobile_node {
	struct in6_addr home_addr;
	struct in6_addr co_addr;
	struct in6_addr ha_addr;
} mobile_node_t;

#define MIP_MN_MOVED		1
#define MIP_BCE_DELETE		2
#define MIP_CB_DEREGISTER	3

int mip_get_all_mobile_nodes(mobile_node_t **mn_list, int local);

int mip_get_one_mobile_node(mobile_node_t *mobile_node);

int mip_notify_movement(mobile_node_t *mobile_node,  
			int non_blocking, 
			unsigned int timeout_ms, 
			long int cb_parameter, 
			int (*callback) (
				mobile_node_t *mobile_node, 
				int event, 
				long int cb_parameter));

/* This macro returns non-zero if the mobile node is at home (i.e. at
 * least one of the care of addresses is same as the home address of
 * the mobile node); otherwise it returns zero.
 */
#define IS_AT_HOME(t) \
	IN6_ARE_ADDR_EQUAL(&((t)->home_addr), &((t)->co_addr))

#endif /* __LIBMIP6_H__ */
