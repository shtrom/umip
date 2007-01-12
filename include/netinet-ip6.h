#ifndef _NETINET__IP6_H
#define _NETINET__IP6_H 1

/* Home Address Destination Option */
struct ip6_opt_home_address {
	uint8_t		ip6oha_type;
	uint8_t		ip6oha_len;
	uint8_t		ip6oha_addr[16];/* Home Address */
} __attribute((packed));

#ifndef IP6OPT_PAD0
#define IP6OPT_PAD0		0x0
#endif
#ifndef IP6OPT_PADN
#define IP6OPT_PADN		0x1
#endif
#ifndef IP6OPT_HOME_ADDRESS
#define IP6OPT_HOME_ADDRESS	0xc9	/* 11 0 01001 */ 
#endif

/* Type 2 Routing header for Mobile IPv6 */
struct ip6_rthdr2 {
	uint8_t		ip6r2_nxt;	/* next header */
	uint8_t		ip6r2_len;	/* length : always 2 */
	uint8_t		ip6r2_type;	/* always 2 */
	uint8_t		ip6r2_segleft;	/* segments left: always 1 */
	uint32_t	ip6r2_reserved;	/* reserved field */
	struct in6_addr	ip6r2_homeaddr;	/* Home Address */
} __attribute((packed));

#endif	/* netinet/ip6.h */
