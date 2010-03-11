#ifndef __NAT_H__
#define __NAT_H__ 1

#define NATKATIMEOUT	110

struct encap_info {
	struct in_addr src;
	uint16_t port;
};

#endif
