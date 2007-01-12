/* $Id: mipapi.h 1.3 05/02/01 12:42:27+02:00 anttit@tcs.hut.fi $ */

#ifndef __MIPAPI_H__
#define __MIPAPI_H__ 1

int mipapi_event(unsigned int event,
		 const struct in6_addr *home_addr,
		 const struct in6_addr *coa,
		 const struct in6_addr *ha_addr);

int libmip6_ipc_init(void);

void libmip6_ipc_fini(void);

#endif
