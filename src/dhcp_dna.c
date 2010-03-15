/* @(#)dhcp_dna.c

 Copyright 2007 Debian User

 Author: lorchat@videonet

 Created : 13 Feb 2007

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <pthread.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/ipv6_route.h>
#include <linux/in_route.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <src/debug.h>

#include "rtnl.h"
#include "movement.h"
#include "dhcp_dna.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/ioctl.h>

#include "conf.h"

/*
  Global variables and pthread related stuff
*/

static pthread_t dhcp_listener;

struct dhcp_message {
        u_int8_t op;
        u_int8_t htype;
        u_int8_t hlen;
        u_int8_t hops;
        u_int32_t xid;
        u_int16_t secs;
        u_int16_t flags;
        u_int32_t ciaddr;
        u_int32_t yiaddr;
        u_int32_t siaddr;
        u_int32_t giaddr;
        u_int8_t chaddr[16];
        u_int8_t sname[64];
        u_int8_t file[128];
        u_int32_t cookie;
        u_int8_t options[308]; /* 312 - cookie */
};

struct udp_dhcp_packet {
        struct iphdr ip;
        struct udphdr udp;
        struct dhcp_message data;
};

/* ------------------------ beginning of client initialization code ------------------------ */

static void change_mode(struct dhcp_dna_control_s *, int);
static void *dhcp_listen (void *);
void run_script_deconfig(struct dhcp_dna_control_s *);
void run_script_renew(struct dhcp_dna_control_s *, struct dhcp_message *);
void run_script_bound(struct dhcp_dna_control_s *, struct dhcp_message *);
void run_script_nak(struct dhcp_dna_control_s *, struct dhcp_message *);
int send_discover(struct dhcp_dna_control_s *, unsigned long, unsigned long);
int send_selecting(struct dhcp_dna_control_s *, unsigned long, unsigned long, unsigned long);
int send_renew(struct dhcp_dna_control_s *, unsigned long, unsigned long, unsigned long);
int send_release(struct dhcp_dna_control_s *, unsigned long, unsigned long );
int listen_socket(unsigned int, int, char *);
int raw_socket(int);
unsigned long random_xid(void);
int get_packet(struct dhcp_message *, int);
int get_raw_packet(struct dhcp_message *, int);
unsigned char *get_option(struct dhcp_message *, int);
int add_simple_option(unsigned char *, unsigned char, u_int32_t);
int read_interface_hwaddr(char *, unsigned char *);

int
dhcp_dna_init(void)
{
  struct list_head *l;
  struct dhcp_dna_control_s *dhcp_ctrl;

  /* Preethi N <prenatar@cisco.com>
   * Support external DCHP client in DSMIP
   * Test if dhcp_listen() thread must be started
   */
  int start_dhcp_listener = 0;

  list_for_each(l, &conf.net_ifaces) {
	struct net_iface *iface;

	iface = list_entry(l, struct net_iface, list);
	dhcp_ctrl = iface->dhcp_ctrl;
	if (dhcp_ctrl != NULL) {
		memset(dhcp_ctrl, 0, sizeof(*dhcp_ctrl));

		dhcp_ctrl->state = DHCP_INIT_SELECTING;
		run_script_deconfig(dhcp_ctrl); /* or any bootstrap mechanism ? */
		change_mode(dhcp_ctrl, DHCP_DNA_LISTEN_MODE_RAW);

		/* TODO :
		   . call to read_interface to guess if_index in dhcp_ctrl struct
		   . define a way to exit dhcp thread
		*/
		if (read_interface_hwaddr(iface->name, dhcp_ctrl->arp) < 0)
		  return -1;

		dhcp_ctrl->if_index = iface->ifindex;

		dhcp_ctrl->clientid = malloc(6 + 3);
		dhcp_ctrl->clientid[DHCP_OPT_CODE] = DHCP_CLIENT_ID;
		dhcp_ctrl->clientid[DHCP_OPT_LEN] = 7;
		dhcp_ctrl->clientid[DHCP_OPT_DATA] = 1;
		memcpy(dhcp_ctrl->clientid + 3, dhcp_ctrl->arp, 6);

		start_dhcp_listener = 1;
	}
	else {
		fprintf(stderr, "dhcp_dna: DHCP disabled for interface: %d (%s)\n", iface->ifindex, iface->name);
	}

  }

  /* Preethi N <prenatar@cisco.com>
   * Support external DCHP client in DSMIP
   */
  if (start_dhcp_listener) {
	if (pthread_create(&dhcp_listener, NULL, dhcp_listen, NULL))
    		return -1;
  }
  else {
	fprintf(stderr, "dhcp_dna: dhcp_listen thread NOT started\n");
  }

  return 0;
}

/* ------------------------ beginning of modified udhcpc code ------------------------ */

/*
   mode switching function

   this only prints a message and resets socket
   socket opening is done in the state machine

 */
static void change_mode(struct dhcp_dna_control_s *dhcp_ctrl, int new_mode)
{
  char *modes[] = { "none", "kernel", "raw" };
  if ( (new_mode < 3) && (new_mode >= 0) )
    fprintf(stderr, "dhcp_dna: dhcp socket changing to listening mode %s\n", modes[new_mode]);

  if (dhcp_ctrl->in_fd > 0)
    close(dhcp_ctrl->in_fd);

  dhcp_ctrl->in_fd = -1;
  dhcp_ctrl->mode = new_mode;
}

/*
  script replacement function for the "deconfig" action
 */
void
run_script_deconfig(struct dhcp_dna_control_s *dhcp_ctrl)
{
}

void
run_script_renew(struct dhcp_dna_control_s *dhcp_ctrl, struct dhcp_message *m)
{
  fprintf(stderr, "renewing lease\n");
}

void
run_script_bound(struct dhcp_dna_control_s *dhcp_ctrl, struct dhcp_message *m)
{
  unsigned char *subnet, *router, *ip;
  unsigned long gateway, netmask;

  /*
     subnet : option 0x01
     router : option 0x03
   */
  subnet = get_option(m, DHCP_SUBNET);
  router = get_option(m, DHCP_ROUTER);
  ip = (unsigned char *) (&m->yiaddr);
  netmask = *( (unsigned long *) subnet);
  gateway = *( (unsigned long *) router);

  fprintf(stderr, "recording address %d.%d.%d.%d, netmask %d.%d.%d.%d, router %d.%d.%d.%d\n",
	  ip[0], ip[1], ip[2], ip[3],
	  subnet[0], subnet[1], subnet[2], subnet[3],
	  router[0], router[1], router[2], router[3]);

  dhcp_ctrl->gateway = gateway;
  dhcp_ctrl->netmask = netmask;
}

void
run_script_nak(struct dhcp_dna_control_s *dhcp_ctrl, struct dhcp_message *m)
{
  fprintf(stderr, "dhcp nak\n");
}

/*
  main state machine code, derived from udhcpc and made into a thread
 */
static void *dhcp_listen (void *arg)
{
  struct timeval tv;
  fd_set rfds;
  int retval;
  time_t now;
  int len, maxfd = -1;
  unsigned char *temp, *message;
  struct dhcp_message packet;
  struct in_addr temp_addr;
  struct md_inet6_iface *curr_iface;

  unsigned long min_time = ((unsigned long)~0UL);
  struct list_head *l;

  pthread_dbg("thread started (dhcp_dna)");

  while (1) {
    maxfd = -1;
    min_time = 0x7fffffff;
    FD_ZERO(&rfds);

    list_for_each(l, &conf.net_ifaces) {
      struct net_iface *iface;
      struct dhcp_dna_control_s *dhcp_ctrl;

      iface = list_entry(l, struct net_iface, list);
      dhcp_ctrl = iface->dhcp_ctrl;
      if (dhcp_ctrl != NULL) {

      if (dhcp_ctrl->timeout < min_time) {
	fprintf(stderr, "dhcp_dna: updating with timeout %lu\n", dhcp_ctrl->timeout);
	min_time = dhcp_ctrl->timeout;
      }

      if (dhcp_ctrl->mode != DHCP_DNA_LISTEN_MODE_NONE && dhcp_ctrl->in_fd < 0) {
	if (dhcp_ctrl->mode == DHCP_DNA_LISTEN_MODE_KERNEL)
	  dhcp_ctrl->in_fd = listen_socket(INADDR_ANY, DHCP_CLIENT_PORT, iface->name);
	else
	  dhcp_ctrl->in_fd = raw_socket(dhcp_ctrl->if_index);
	if (dhcp_ctrl->in_fd < 0) {
	  fprintf(stderr, "dhcp_dna: couldn't listen on socket (%s)\n", strerror(errno));
	  pthread_exit(NULL);
	}
      }

      if (dhcp_ctrl->in_fd >= 0) {
	FD_SET(dhcp_ctrl->in_fd, &rfds);
	if (dhcp_ctrl->in_fd > maxfd) {
	  maxfd = dhcp_ctrl->in_fd;
          fprintf(stderr, "dhcp_dna: watching on socket %d\n", maxfd);
        }
      }
      }
    }

    tv.tv_sec = min_time - time(0);
    tv.tv_usec = 0;

    if (tv.tv_sec > 0) {
      fprintf(stderr, "dhcp_dna: waiting on select\n");
      retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    } else
      retval = 0; /* timeout reached somehow */

    now = time(0);
    if (retval == 0) {
      /* timeout dropped to zero */
      list_for_each(l, &conf.net_ifaces) {
	struct net_iface *iface;
	struct dhcp_dna_control_s *dhcp_ctrl;

	iface = list_entry(l, struct net_iface, list);
	dhcp_ctrl = iface->dhcp_ctrl;
	if (dhcp_ctrl != NULL) {

	fprintf(stderr, "timeout : %lu and now is %lu\n", dhcp_ctrl->timeout, now);

	if (dhcp_ctrl->timeout <= now) {

	  switch (dhcp_ctrl->state) {
	  case DHCP_POLL:
	    fprintf(stderr, "dhcp_dna: still in polling mode...\n");
	    dhcp_ctrl->timeout = now + 1;
	    break;
	  case DHCP_INIT_SELECTING:
	    if (dhcp_ctrl->seq_num < 3) {
	      if (dhcp_ctrl->seq_num == 0)
		dhcp_ctrl->xid = random_xid();

	      /* send discover packet */
	      send_discover(dhcp_ctrl, dhcp_ctrl->xid, dhcp_ctrl->requested_ip); /* broadcast */

	      dhcp_ctrl->timeout = now + ((dhcp_ctrl->seq_num == 2) ? 4 : 2);
	      dhcp_ctrl->seq_num++;
	    } else {
	      /* wait to try again */
	      //fprintf(stderr, "dhcp_dna: no lease obtained, sleeping for 1 minute\n");
	      fprintf(stderr, "dhcp_dna: no lease obtained, entering polling mode\n");
	      dhcp_ctrl->state = DHCP_POLL;
	      dhcp_ctrl->seq_num = 0;
	      //dhcp_ctrl->timeout = now + 60;
	      dhcp_ctrl->timeout = now + 1;
	    }
	    break;
	  case DHCP_RENEW_REQUESTED:
	  case DHCP_REQUESTING:
	    if (dhcp_ctrl->seq_num < 3) {
	      /* send request packet */
	      if (dhcp_ctrl->state == DHCP_RENEW_REQUESTED)
		send_renew(dhcp_ctrl, dhcp_ctrl->xid, dhcp_ctrl->server, dhcp_ctrl->requested_ip); /* unicast */
	      else send_selecting(dhcp_ctrl, dhcp_ctrl->xid, dhcp_ctrl->server, dhcp_ctrl->requested_ip); /* broadcast */

	      dhcp_ctrl->timeout = now + ((dhcp_ctrl->seq_num == 2) ? 10 : 2);
	      dhcp_ctrl->seq_num++;
	    } else {
	      /* timed out, go back to init state */
	      if (dhcp_ctrl->state == DHCP_RENEW_REQUESTED)
		run_script_deconfig(dhcp_ctrl);
	      dhcp_ctrl->state = DHCP_INIT_SELECTING;
	      dhcp_ctrl->timeout = now;
	      dhcp_ctrl->seq_num = 0;
	      change_mode(dhcp_ctrl, DHCP_DNA_LISTEN_MODE_RAW);
	    }
	    break;
	  case DHCP_BOUND:
	    /* Lease is starting to run out, time to enter renewing state */
	    dhcp_ctrl->state = DHCP_RENEWING;
	    change_mode(dhcp_ctrl, DHCP_DNA_LISTEN_MODE_KERNEL);
	    fprintf(stderr, "dhcp_dna: entering renew state\n");
	    /* fall right through */
	  case DHCP_RENEWING:
	    /* Either set a new T1, or enter REBINDING state */
	    if ((dhcp_ctrl->t2 - dhcp_ctrl->t1) <= (dhcp_ctrl->lease / 14400 + 1)) {
	      /* timed out, enter rebinding state */
	      dhcp_ctrl->state = DHCP_REBINDING;
	      dhcp_ctrl->timeout = now + (dhcp_ctrl->t2 - dhcp_ctrl->t1);
	      fprintf(stderr, "dhcp_dna: entering rebinding state\n");
	    } else {
	      /* send a request packet */
	      send_renew(dhcp_ctrl, dhcp_ctrl->xid, dhcp_ctrl->server, dhcp_ctrl->requested_ip); /* unicast */

	      dhcp_ctrl->t1 = (dhcp_ctrl->t2 - dhcp_ctrl->t1) / 2 + dhcp_ctrl->t1;
	      dhcp_ctrl->timeout = dhcp_ctrl->t1 + dhcp_ctrl->start;
	    }
	    break;
	  case DHCP_REBINDING:
	    /* Either set a new T2, or enter INIT state */
	    if ((dhcp_ctrl->lease - dhcp_ctrl->t2) <= (dhcp_ctrl->lease / 14400 + 1)) {
	      /* timed out, enter init state */
	      dhcp_ctrl->state = DHCP_INIT_SELECTING;
	      fprintf(stderr, "dhcp_dna: lease lost, entering init state");
	      run_script_deconfig(dhcp_ctrl);
	      dhcp_ctrl->timeout = now;
	      dhcp_ctrl->seq_num = 0;
	      change_mode(dhcp_ctrl, DHCP_DNA_LISTEN_MODE_RAW);
	    } else {
	      /* send a request packet */
	      send_renew(dhcp_ctrl, dhcp_ctrl->xid, 0, dhcp_ctrl->requested_ip); /* broadcast */

	      dhcp_ctrl->t2 = (dhcp_ctrl->lease - dhcp_ctrl->t2) / 2 + dhcp_ctrl->t2;
	      dhcp_ctrl->timeout = dhcp_ctrl->t2 + dhcp_ctrl->start;
	    }
	    break;
	  case DHCP_RELEASED:
	    /* yah, I know, *you* say it would never happen */
	    dhcp_ctrl->timeout = 0x7fffffff;
	    break;
	  }
	}
	}
      }
    } else {

      list_for_each(l, &conf.net_ifaces) {
	struct net_iface *iface;
	struct dhcp_dna_control_s *dhcp_ctrl;

	iface = list_entry(l, struct net_iface, list);
	dhcp_ctrl = iface->dhcp_ctrl;
	if (dhcp_ctrl != NULL) {

	if (retval > 0
	    && dhcp_ctrl->mode != DHCP_DNA_LISTEN_MODE_NONE
	    && FD_ISSET(dhcp_ctrl->in_fd, &rfds)) {
	  /* a packet is ready, read it */

	  if (dhcp_ctrl->mode == DHCP_DNA_LISTEN_MODE_KERNEL)
	    len = get_packet(&packet, dhcp_ctrl->in_fd);
	  else len = get_raw_packet(&packet, dhcp_ctrl->in_fd);

	  if (len == -1 && errno != EINTR) {
	    fprintf(stderr, "dhcp_dna: error on read (%s), reopening socket\n", strerror(errno));
	    change_mode(dhcp_ctrl, dhcp_ctrl->mode); /* just close and reopen */
	  }

	  if (len < 0)
	    continue;

	  if (packet.xid != dhcp_ctrl->xid) {
	    fprintf(stderr, "dhcp_dna: ignoring XID %lx (our xid is %lx)",
		    (unsigned long) packet.xid, dhcp_ctrl->xid);
	    continue;
	  }

	  if ((message = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
	    fprintf(stderr, "dhcp_dna: couldnt get option from packet -- ignoring\n");
	    continue;
	  }

	  switch (dhcp_ctrl->state) {
	  case DHCP_INIT_SELECTING:
	    /* Must be a DHCPOFFER to one of our xid's */
	    if (*message == DHCPOFFER) {
	      if ((temp = get_option(&packet, DHCP_SERVER_ID))) {
		memcpy(&dhcp_ctrl->server, temp, 4);
		dhcp_ctrl->xid = packet.xid;
		dhcp_ctrl->requested_ip = packet.yiaddr;

		/* enter requesting state */
		dhcp_ctrl->state = DHCP_REQUESTING;
		dhcp_ctrl->timeout = now;
		dhcp_ctrl->seq_num = 0;
	      } else {
		fprintf(stderr, "dhcp_dna: no server ID in message\n");
	      }
	    }
	    break;
	  case DHCP_RENEW_REQUESTED:
	  case DHCP_REQUESTING:
	  case DHCP_RENEWING:
	  case DHCP_REBINDING:
	    if (*message == DHCPACK) {
	      if (!(temp = get_option(&packet, DHCP_LEASE_TIME))) {
		fprintf(stderr, "dhcp_dna: no lease time with ACK, using 1 hour lease\n");
		dhcp_ctrl->lease = 60 * 60;
	      } else {
		memcpy(&dhcp_ctrl->lease, temp, 4);
		dhcp_ctrl->lease = ntohl(dhcp_ctrl->lease);
	      }

	      /* enter bound state */
	      dhcp_ctrl->t1 = dhcp_ctrl->lease / 2;

	      /* little fixed point for n * .875 */
	      dhcp_ctrl->t2 = (dhcp_ctrl->lease * 0x7) >> 3;
	      temp_addr.s_addr = packet.yiaddr;
	      fprintf(stderr, "dhcp_dna: lease of %s obtained, lease time %ld",
		      inet_ntoa(temp_addr), dhcp_ctrl->lease);
	      dhcp_ctrl->start = now;
	      dhcp_ctrl->timeout = dhcp_ctrl->t1 + dhcp_ctrl->start;
	      dhcp_ctrl->requested_ip = packet.yiaddr;
	      if ( (dhcp_ctrl->state == DHCP_RENEWING) || (dhcp_ctrl->state == DHCP_REBINDING) )
		run_script_renew(dhcp_ctrl, &packet);
	      else
		run_script_bound(dhcp_ctrl, &packet);

	      dhcp_ctrl->state = DHCP_BOUND;
	      change_mode(dhcp_ctrl, DHCP_DNA_LISTEN_MODE_NONE);

	      // dhcp_status set to DHCP_RUNNING only if
	      // the dhcp_configuration was successful
	      curr_iface = dsmip_get_inet6_iface(dhcp_ctrl->if_index);
	      if (curr_iface == NULL)
	  	fprintf(stderr, "dhcp_dna: Could not get DHCP interface structure\n");
	      if(curr_iface && dhcp_configuration(curr_iface)) {
		curr_iface->dhcp_status |= DHCP_RUNNING;
	      }
	    } else if (*message == DHCPNAK) {
	      /* return to init state */
	      fprintf(stderr, "dhcp_dna: received DHCP NAK");
	      run_script_nak(dhcp_ctrl, &packet);
	      if (dhcp_ctrl->state != DHCP_REQUESTING)
		run_script_deconfig(dhcp_ctrl);
	      dhcp_ctrl->state = DHCP_INIT_SELECTING;
	      dhcp_ctrl->timeout = now;
	      dhcp_ctrl->requested_ip = 0;
	      dhcp_ctrl->seq_num = 0;
	      change_mode(dhcp_ctrl, DHCP_DNA_LISTEN_MODE_RAW);
	      sleep(3); /* avoid excessive network traffic */
	    }
	    break;
	    /* case BOUND, RELEASED: - ignore all packets */
	  }
	}
	}
      }
    }
  }

  pthread_exit(NULL);
}

/* ------------------------ udhcpc derived udp packet crafting code ------------------------ */

void
init_header(struct dhcp_message *packet, char type)
{
  memset(packet, 0, sizeof(struct dhcp_message));
  switch (type) {
  case DHCPDISCOVER:
  case DHCPREQUEST:
  case DHCPRELEASE:
  case DHCPINFORM:
    packet->op = DHCP_BOOTREQUEST;
    break;
  case DHCPOFFER:
  case DHCPACK:
  case DHCPNAK:
    packet->op = DHCP_BOOTREPLY;
  }
  packet->htype = DHCP_ETH_10MB;
  packet->hlen = DHCP_ETH_10MB_LEN;
  packet->cookie = htonl(DHCP_MAGIC);
  packet->options[0] = DHCP_END;
  add_simple_option(packet->options, DHCP_MESSAGE_TYPE, type);
}


/*
   read a packet from socket fd

   return : -1 on read error
            -2 on packet error
*/
int
get_packet(struct dhcp_message *packet, int fd)
{
  int bytes;
  int i;
  const char broken_vendors[][8] = {
    "MSFT 98",
    ""
  };
  char unsigned *vendor;

  memset(packet, 0, sizeof(struct dhcp_message));
  bytes = read(fd, packet, sizeof(struct dhcp_message));
  if (bytes < 0) {
    fprintf(stderr, "dhcp_dna: couldn't read on listening socket, ignoring\n");
    return -1;
  }

  if (ntohl(packet->cookie) != DHCP_MAGIC) {
    fprintf(stderr, "dhcp_dna: received bogus message, ignoring\n");
    return -2;
  }
  fprintf(stderr, "dhcp_dna: received a packet\n");

  if (packet->op == DHCP_BOOTREQUEST &&
      (vendor = get_option(packet, DHCP_VENDOR)))
    {
      for (i = 0; broken_vendors[i][0]; i++) {
	if (vendor[DHCP_OPT_LEN - 2] == (unsigned char) strlen((const char *)broken_vendors[i]) &&
	    !strncmp((const char *)vendor, (const char *)broken_vendors[i], vendor[DHCP_OPT_LEN - 2]))
	  {
	    fprintf(stderr, "dhcp_dna: broken client (%s), forcing broadcast\n",
		    broken_vendors[i]);
	    packet->flags |= htons(DHCP_BROADCAST_FLAG);
	  }
      }
    }

  return bytes;
}


u_int16_t
checksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register int32_t sum = 0;
	u_int16_t *source = (u_int16_t *) addr;

	while (count > 1)  {
		/*  This is the inner loop */
		sum += *source++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		u_int16_t tmp = 0;
		*(unsigned char *) (&tmp) = * (unsigned char *) source;
		sum += tmp;
	}
	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}


/*
   Construct a IP and UDP header for a packet
   and specify the source and dest hardware address
*/
int
raw_packet(struct dhcp_message *payload, u_int32_t source_ip, int source_port,
	   u_int32_t dest_ip, int dest_port, unsigned char *dest_arp, int ifindex)
{
  int fd;
  int result;
  struct sockaddr_ll dest;
  struct udp_dhcp_packet packet;

  if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
    fprintf(stderr, "dhcp_dna: socket call failed: %s\n", strerror(errno));
    return -1;
  }

  memset(&dest, 0, sizeof(dest));
  memset(&packet, 0, sizeof(packet));

  dest.sll_family = AF_PACKET;
  dest.sll_protocol = htons(ETH_P_IP);
  dest.sll_ifindex = ifindex;
  dest.sll_halen = 6;
  memcpy(dest.sll_addr, dest_arp, 6);
  if (bind(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll)) < 0) {
    fprintf(stderr, "dhcp_dna: bind call failed: %s\n", strerror(errno));
    close(fd);
    return -1;
  }

  packet.ip.protocol = IPPROTO_UDP;
  packet.ip.saddr = source_ip;
  packet.ip.daddr = dest_ip;
  packet.udp.source = htons(source_port);
  packet.udp.dest = htons(dest_port);
  packet.udp.len = htons(sizeof(packet.udp) + sizeof(struct dhcp_message)); /* cheat on the psuedo-header */
  packet.ip.tot_len = packet.udp.len;
  memcpy(&(packet.data), payload, sizeof(struct dhcp_message));
  packet.udp.check = checksum(&packet, sizeof(struct udp_dhcp_packet));

  packet.ip.tot_len = htons(sizeof(struct udp_dhcp_packet));
  packet.ip.ihl = sizeof(packet.ip) >> 2;
  packet.ip.version = IPVERSION;
  packet.ip.ttl = IPDEFTTL;
  packet.ip.check = checksum(&(packet.ip), sizeof(packet.ip));

  result = sendto(fd, &packet, sizeof(struct udp_dhcp_packet), 0, (struct sockaddr *) &dest, sizeof(dest));
  if (result <= 0) {
    fprintf(stderr, "dhcp_dna: write on socket failed: %s\n", strerror(errno));
  }

  close(fd);
  return result;
}


/*
   Let the kernel do all the work for packet generation
*/
int kernel_packet(struct dhcp_message *payload, u_int32_t source_ip, int source_port,
		   u_int32_t dest_ip, int dest_port)
{
  int n = 1;
  int fd, result;
  struct sockaddr_in client;

  if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return -1;

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1)
    return -1;

  memset(&client, 0, sizeof(client));
  client.sin_family = AF_INET;
  client.sin_port = htons(source_port);
  client.sin_addr.s_addr = source_ip;

  if (bind(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
    return -1;

  memset(&client, 0, sizeof(client));
  client.sin_family = AF_INET;
  client.sin_port = htons(dest_port);
  client.sin_addr.s_addr = dest_ip;

  if (connect(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
    return -1;

  result = write(fd, payload, sizeof(struct dhcp_message));
  close(fd);
  return result;
}

/* ------------------------ beginning of udhcpc derived code for dhcp options -------------- */

enum {
  DHCP_OPTION_IP=1,
  DHCP_OPTION_IP_PAIR,
  DHCP_OPTION_STRING,
  DHCP_OPTION_BOOLEAN,
  DHCP_OPTION_U8,
  DHCP_OPTION_U16,
  DHCP_OPTION_S16,
  DHCP_OPTION_U32,
  DHCP_OPTION_S32
};

struct dhcp_option dhcp_options[] = {
  /* name[10]	flags					code */
  {"subnet",	DHCP_OPTION_IP | DHCP_OPTION_REQ,			0x01},
  {"timezone",	DHCP_OPTION_S32,				0x02},
  {"router",	DHCP_OPTION_IP | DHCP_OPTION_LIST | DHCP_OPTION_REQ,	0x03},
  {"timesvr",	DHCP_OPTION_IP | DHCP_OPTION_LIST,		0x04},
  {"namesvr",	DHCP_OPTION_IP | DHCP_OPTION_LIST,		0x05},
  {"dns",	DHCP_OPTION_IP | DHCP_OPTION_LIST | DHCP_OPTION_REQ,	0x06},
  {"logsvr",	DHCP_OPTION_IP | DHCP_OPTION_LIST,		0x07},
  {"cookiesvr",	DHCP_OPTION_IP | DHCP_OPTION_LIST,		0x08},
  {"lprsvr",	DHCP_OPTION_IP | DHCP_OPTION_LIST,		0x09},
  {"hostname",	DHCP_OPTION_STRING | DHCP_OPTION_REQ,		0x0c},
  {"bootsize",	DHCP_OPTION_U16,				0x0d},
  {"domain",	DHCP_OPTION_STRING | DHCP_OPTION_REQ,		0x0f},
  {"swapsvr",	DHCP_OPTION_IP,				0x10},
  {"rootpath",	DHCP_OPTION_STRING,				0x11},
  {"ipttl",	DHCP_OPTION_U8,				0x17},
  {"mtu",	DHCP_OPTION_U16,				0x1a},
  {"broadcast",	DHCP_OPTION_IP | DHCP_OPTION_REQ,			0x1c},
  {"ntpsrv",	DHCP_OPTION_IP | DHCP_OPTION_LIST,		0x2a},
  {"wins",	DHCP_OPTION_IP | DHCP_OPTION_LIST,		0x2c},
  {"requestip",	DHCP_OPTION_IP,				0x32},
  {"lease",	DHCP_OPTION_U32,				0x33},
  {"dhcptype",	DHCP_OPTION_U8,				0x35},
  {"serverid",	DHCP_OPTION_IP,				0x36},
  {"message",	DHCP_OPTION_STRING,				0x38},
  {"tftp",	DHCP_OPTION_STRING,				0x42},
  {"bootfile",	DHCP_OPTION_STRING,				0x43},
  {"",		0x00,					0x00}
};

/* Lengths of the different option types */
int dhcp_option_lengths[] = {
  [DHCP_OPTION_IP] =		4,
  [DHCP_OPTION_IP_PAIR] =	8,
  [DHCP_OPTION_BOOLEAN] =	1,
  [DHCP_OPTION_STRING] =	1,
  [DHCP_OPTION_U8] =		1,
  [DHCP_OPTION_U16] =	2,
  [DHCP_OPTION_S16] =	2,
  [DHCP_OPTION_U32] =	4,
  [DHCP_OPTION_S32] =	4
};

/*
   get an option with bounds checking (warning, not aligned).
*/
unsigned char *
get_option(struct dhcp_message *packet, int code)
{
  int i, length;
  unsigned char *optionptr;
  int over = 0, done = 0, curr = DHCP_OPTION_FIELD;

  optionptr = packet->options;
  i = 0;
  length = 308;
  while (!done) {

    if (i >= length) {
      fprintf(stderr, "dhcp_dna: bogus packet, option fields too long.\n");
      return NULL;
    }

    if (optionptr[i + DHCP_OPT_CODE] == code)
      {
	if (i + 1 + optionptr[i + DHCP_OPT_LEN] >= length)
	  {
	    fprintf(stderr, "dhcp_dna: bogus packet, option fields too long.\n");
	    return NULL;
	  }
	return optionptr + i + 2;
      }

    switch (optionptr[i + DHCP_OPT_CODE]) {
    case DHCP_PADDING:
      i++;
      break;
    case DHCP_OPTION_OVER:
      if (i + 1 + optionptr[i + DHCP_OPT_LEN] >= length) {
	fprintf(stderr, "dhcp_dna: bogus packet, option fields too long.\n");
	return NULL;
      }
      over = optionptr[i + 3];
      i += optionptr[DHCP_OPT_LEN] + 2;
      break;
    case DHCP_END:
      if (curr == DHCP_OPTION_FIELD && over & DHCP_FILE_FIELD) {
	optionptr = packet->file;
	i = 0;
	length = 128;
	curr = DHCP_FILE_FIELD;
      } else if (curr == DHCP_FILE_FIELD && over & DHCP_SNAME_FIELD) {
	optionptr = packet->sname;
	i = 0;
	length = 64;
	curr = DHCP_SNAME_FIELD;
      } else done = 1;
      break;
    default:
      i += optionptr[DHCP_OPT_LEN + i] + 2;
    }
  }
  return NULL;
}


/*
   return the position of the 'end' option (no bounds checking)
*/
int
end_option(unsigned char *optionptr)
{
  int i = 0;

  while (optionptr[i] != DHCP_END) {
    if (optionptr[i] == DHCP_PADDING) i++;
    else i += optionptr[i + DHCP_OPT_LEN] + 2;
  }
  return i;
}


/*
   add an option string to the options
   (an option string contains an option code, length, then data)

   heh, it looks so much like that TLV stuff
*/
int
add_option_string(unsigned char *optionptr, unsigned char *string)
{
  int end = end_option(optionptr);

  /* end position + string length + option code/length + end option */
  if (end + string[DHCP_OPT_LEN] + 2 + 1 >= 308) {
    fprintf(stderr, "dhcp_dna: Option 0x%02x did not fit into the packet!\n", string[DHCP_OPT_CODE]);
    return 0;
  }

  fprintf(stderr, "dhcp_dna: adding option 0x%02x\n", string[DHCP_OPT_CODE]);
  memcpy(optionptr + end, string, string[DHCP_OPT_LEN] + 2);
  optionptr[end + string[DHCP_OPT_LEN] + 2] = DHCP_END;

  return string[DHCP_OPT_LEN] + 2;
}


/*
   add a one to four byte option to a packet
*/
int
add_simple_option(unsigned char *optionptr, unsigned char code, u_int32_t data)
{
  char length = 0;
  int i;
  unsigned char option[2 + 4];
  unsigned char *u8;
  u_int16_t *u16;
  u_int32_t *u32;
  u_int32_t aligned;
  u8 = (unsigned char *) &aligned;
  u16 = (u_int16_t *) &aligned;
  u32 = &aligned;

  for (i = 0; dhcp_options[i].code; i++)
    if (dhcp_options[i].code == code) {
      length = dhcp_option_lengths[dhcp_options[i].flags & DHCP_TYPE_MASK];
    }

  if (!length) {
    fprintf(stderr, "dhcp_dna: could not add option 0x%02x\n", code);
    return 0;
  }

  option[DHCP_OPT_CODE] = code;
  option[DHCP_OPT_LEN] = length;

  switch (length) {
  case 1: *u8 =  data; break;
  case 2: *u16 = data; break;
  case 4: *u32 = data; break;
  }

  memcpy(option + 2, &aligned, length);
  return add_option_string(optionptr, option);
}


/*
   find option 'code' in opt_list
*/
struct option_set *
find_option(struct option_set *opt_list, char code)
{
  while (opt_list && opt_list->data[DHCP_OPT_CODE] < code)
    opt_list = opt_list->next;

  if (opt_list && opt_list->data[DHCP_OPT_CODE] == code)
    return opt_list;
  else
    return NULL;
}


/*
   add an option to the opt_list
*/
void
attach_option(struct option_set **opt_list, struct dhcp_option *option, char *buffer, int length)
{
  struct option_set *existing, *new, **curr;

  /* add it to an existing option */
  if ((existing = find_option(*opt_list, option->code)))
    {
    fprintf(stderr, "dhcp_dna: attaching option %s to existing member of list\n", option->name);
    if (option->flags & DHCP_OPTION_LIST)
      {
	if (existing->data[DHCP_OPT_LEN] + length <= 255)
	  {
	    existing->data = realloc(existing->data,
				     existing->data[DHCP_OPT_LEN] + length + 2);
	    memcpy(existing->data + existing->data[DHCP_OPT_LEN] + 2, buffer, length);
	    existing->data[DHCP_OPT_LEN] += length;
	  } /* else, ignore the data, we could put this in a second option in the future */
      } /* else, ignore the new data */
    }
  else
    {
      fprintf(stderr, "dhcp_dna: attaching option %s to list\n", option->name);

      /* make a new option */
      new = malloc(sizeof(struct option_set));
      new->data = malloc(length + 2);
      new->data[DHCP_OPT_CODE] = option->code;
      new->data[DHCP_OPT_LEN] = length;
      memcpy(new->data + 2, buffer, length);

      curr = opt_list;
      while (*curr && (*curr)->data[DHCP_OPT_CODE] < option->code)
	curr = &(*curr)->next;

      new->next = *curr;
      *curr = new;
    }
}

/* ------------------------ udhcpc derived packet code ------------------------ */

/*
   Create a random xid, based on (hopefully) random data from /dev/urandom
*/
unsigned long
random_xid(void)
{
  static int initialized;

  if (!initialized) {
    int fd;
    unsigned long seed;

    fd = open("/dev/urandom", 0);
    if (fd < 0 || read(fd, &seed, sizeof(seed)) < 0)
      {
	fprintf(stderr, "dhcp_dna: could not load seed from /dev/urandom: %s\n",
		strerror(errno));
	seed = time(0);
      }

    if (fd >= 0) close(fd);
    srand(seed);
    initialized++;
  }

  return rand();
}


/*
  initialize a packet with the proper defaults
*/
static void
init_packet(struct dhcp_dna_control_s *dhcp_ctrl, struct dhcp_message *packet, char type)
{
  struct vendor  {
    char vendor, length;
    char str[sizeof("umip 0.4")];
  } vendor_id = { DHCP_VENDOR, sizeof("umip 0.4") - 1, "umip 0.4"};

  init_header(packet, type);
  memcpy(packet->chaddr, dhcp_ctrl->arp, 6);
  add_option_string(packet->options, dhcp_ctrl->clientid);
  /*  if (client_config.hostname) add_option_string(packet->options, client_config.hostname);*/
  add_option_string(packet->options, (unsigned char *) &vendor_id);
}


/*
   Add a paramater request list for stubborn DHCP servers. Pull the data
   from the struct in options.c. Don't do bounds checking here because it
   goes towards the head of the packet.
*/
static void
add_requests(struct dhcp_message *packet)
{
  int end = end_option(packet->options);
  int i, len = 0;

  packet->options[end + DHCP_OPT_CODE] = DHCP_PARAM_REQ;
  for (i = 0; dhcp_options[i].code; i++)
    if (dhcp_options[i].flags & DHCP_OPTION_REQ)
      packet->options[end + DHCP_OPT_DATA + len++] = dhcp_options[i].code;
  packet->options[end + DHCP_OPT_LEN] = len;
  packet->options[end + DHCP_OPT_DATA + len] = DHCP_END;

}


/*
  Broadcast a DHCP discover packet to the network
  with an optionally requested IP
*/
int
send_discover(struct dhcp_dna_control_s *dhcp_ctrl, unsigned long xid, unsigned long requested)
{
  struct dhcp_message packet;

  init_packet(dhcp_ctrl, &packet, DHCPDISCOVER);
  packet.xid = xid;
  if (requested)
    add_simple_option(packet.options, DHCP_REQUESTED_IP, requested);

  add_requests(&packet);
  fprintf(stderr, "dhcp_dna: sending discover...\n");

  return raw_packet(&packet, INADDR_ANY, DHCP_CLIENT_PORT, INADDR_BROADCAST,
		    DHCP_SERVER_PORT, DHCP_MAC_BCAST_ADDR, dhcp_ctrl->if_index);
}


/*
   Broadcasts a DHCP request message
*/
int
send_selecting(struct dhcp_dna_control_s *dhcp_ctrl, unsigned long xid, unsigned long server, unsigned long requested)
{
	struct dhcp_message packet;
	struct in_addr addr;

	init_packet(dhcp_ctrl, &packet, DHCPREQUEST);
	packet.xid = xid;

	add_simple_option(packet.options, DHCP_REQUESTED_IP, requested);
	add_simple_option(packet.options, DHCP_SERVER_ID, server);

	add_requests(&packet);
	addr.s_addr = requested;
	fprintf(stderr, "dhcp_dna: sending select for %s...\n", inet_ntoa(addr));

	return raw_packet(&packet, INADDR_ANY, DHCP_CLIENT_PORT, INADDR_BROADCAST,
			  DHCP_SERVER_PORT, DHCP_MAC_BCAST_ADDR, dhcp_ctrl->if_index);
}


/*
   Unicasts or broadcasts a DHCP renew message
*/
int
send_renew(struct dhcp_dna_control_s *dhcp_ctrl, unsigned long xid, unsigned long server, unsigned long ciaddr)
{
  struct dhcp_message packet;
  int ret = 0;

  init_packet(dhcp_ctrl, &packet, DHCPREQUEST);
  packet.xid = xid;
  packet.ciaddr = ciaddr;

  add_requests(&packet);
  fprintf(stderr, "dhcp_dna: sending renew...\n");

  if (server)
    ret = kernel_packet(&packet, ciaddr, DHCP_CLIENT_PORT, server, DHCP_SERVER_PORT);
  else
    ret = raw_packet(&packet, INADDR_ANY, DHCP_CLIENT_PORT, INADDR_BROADCAST,
		     DHCP_SERVER_PORT, DHCP_MAC_BCAST_ADDR, dhcp_ctrl->if_index);

  return ret;
}


/*
  Unicasts a DHCP release message
*/
int
send_release(struct dhcp_dna_control_s *dhcp_ctrl, unsigned long server, unsigned long ciaddr)
{
  struct dhcp_message packet;

  init_packet(dhcp_ctrl, &packet, DHCPRELEASE);
  packet.xid = random_xid();
  packet.ciaddr = ciaddr;

  add_simple_option(packet.options, DHCP_REQUESTED_IP, ciaddr);
  add_simple_option(packet.options, DHCP_SERVER_ID, server);

  fprintf(stderr, "dhcp_dna: sending release...\n");

  return kernel_packet(&packet, ciaddr, DHCP_CLIENT_PORT, server, DHCP_SERVER_PORT);
}


/*
  return: -1 on errors that are fatal for the socket
          -2 for those that are not
*/
int get_raw_packet(struct dhcp_message *payload, int fd)
{
  int bytes;
  struct udp_dhcp_packet packet;
  u_int32_t source, dest;
  u_int16_t check;

  memset(&packet, 0, sizeof(struct udp_dhcp_packet));
  bytes = read(fd, &packet, sizeof(struct udp_dhcp_packet));
  if (bytes < 0) {
    fprintf(stderr, "dhcp_dna: couldn't read on raw listening socket, ignoring\n");
    usleep(500000); /* possible down interface, looping condition */
    return -1;
  }

  if (bytes < (int) (sizeof(struct iphdr) + sizeof(struct udphdr))) {
    fprintf(stderr, "dhcp_dna: message too short, ignoring\n");
    return -2;
  }

  if (bytes < ntohs(packet.ip.tot_len)) {
    fprintf(stderr, "dhcp_dna: truncated packet\n");
    return -2;
  }

  /* ignore any extra garbage bytes */
  bytes = ntohs(packet.ip.tot_len);

  /* Make sure its the right packet for us, and that it passes sanity checks */
  if (packet.ip.protocol != IPPROTO_UDP || packet.ip.version != IPVERSION ||
      packet.ip.ihl != sizeof(packet.ip) >> 2 || packet.udp.dest != htons(DHCP_CLIENT_PORT) ||
      bytes > (int) sizeof(struct udp_dhcp_packet) ||
      ntohs(packet.udp.len) != (short) (bytes - sizeof(packet.ip)))
    {
      fprintf(stderr, "dhcp_dna: unrelated/bogus packet\n");
      return -2;
    }

  /* check IP checksum */
  check = packet.ip.check;
  packet.ip.check = 0;
  if (check != checksum(&(packet.ip), sizeof(packet.ip))) {
    fprintf(stderr, "dhcp_dna: bad IP header checksum, ignoring\n");
    return -1;
  }

  /* verify the UDP checksum by replacing the header with a psuedo header */
  source = packet.ip.saddr;
  dest = packet.ip.daddr;
  check = packet.udp.check;
  packet.udp.check = 0;
  memset(&packet.ip, 0, sizeof(packet.ip));

  packet.ip.protocol = IPPROTO_UDP;
  packet.ip.saddr = source;
  packet.ip.daddr = dest;
  packet.ip.tot_len = packet.udp.len; /* cheat on the psuedo-header */
  if (check && check != checksum(&packet, bytes)) {
    fprintf(stderr, "dhcp_dna: packet with bad UDP checksum received, ignoring\n");
    return -2;
  }

  memcpy(payload, &(packet.data), bytes - (sizeof(packet.ip) + sizeof(packet.udp)));

  if (ntohl(payload->cookie) != DHCP_MAGIC) {
    fprintf(stderr, "dhcp_dna: received bogus message (bad magic), ignoring\n");
    return -2;
  }

  fprintf(stderr, "dhcp_dna: DHCP packet received\n");
  return bytes - (sizeof(packet.ip) + sizeof(packet.udp));
}

/* --------------------- low level socket and interfaces related code --------------------------*/

/*
  Resolve interface index and mac address based on user friendly name
 */
int
read_interface_hwaddr(char *interface, unsigned char *arp)
{
  int fd;
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(struct ifreq));
  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
      fprintf(stderr, "dhcp_dna: adapter index %d", ifr.ifr_ifindex);
    } else {
      fprintf(stderr, "dhcp_dna: SIOCGIFINDEX failed!: %s", strerror(errno));
      return -1;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
      memcpy(arp, ifr.ifr_hwaddr.sa_data, 6);
      fprintf(stderr, "dhcp_dna: adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x",
	      arp[0], arp[1], arp[2], arp[3], arp[4], arp[5]);
    } else {
      fprintf(stderr, "SIOCGIFHWADDR failed!: %s", strerror(errno));
      return -1;
    }

  } else {
    fprintf(stderr, "dhcp_dna: socket failed!: %s", strerror(errno));
    return -1;
  }
  close(fd);
  return 0;
}


int listen_socket(unsigned int ip, int port, char *inf)
{
  struct ifreq interface;
  int fd;
  struct sockaddr_in addr;
  int n = 1;

  fprintf(stderr, "dhcp_dna: Opening listen socket on 0x%08x:%d %s\n", ip, port, inf);
  if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    fprintf(stderr, "dhcp_dna: socket call failed: %s", strerror(errno));
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = ip;

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1) {
    close(fd);
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *) &n, sizeof(n)) == -1) {
    close(fd);
    return -1;
  }

  strncpy(interface.ifr_ifrn.ifrn_name, inf, IFNAMSIZ);
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,(char *)&interface, sizeof(interface)) < 0) {
    close(fd);
    return -1;
  }

  if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1) {
    close(fd);
    return -1;
  }

  return fd;
}


int raw_socket(int ifindex)
{
  int fd;
  struct sockaddr_ll sock;

  fprintf(stderr, "dhcp_dna: opening raw socket on ifindex %d\n", ifindex);
  if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
    fprintf(stderr, "dhcp_dna: socket call failed: %s", strerror(errno));
    return -1;
  }

  sock.sll_family = AF_PACKET;
  sock.sll_protocol = htons(ETH_P_IP);
  sock.sll_ifindex = ifindex;
  if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
    fprintf(stderr, "dhcp_dna: bind call failed: %s", strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

/* ------------------------ beginning of mipl daemon specific code ------------------------ */

void
dna_reachability_check(struct md_inet6_iface *iface)
{
  /* see RFC 4436 */
}

int dsmip_v4coa_add(struct ifaddrmsg *ifa, struct rtattr *rta_tb[], void *arg)
{
	struct in6_addr *addr = RTA_DATA(rta_tb[IFA_ADDRESS]);

	//	addr_del(addr, ifa->ifa_prefixlen, ifa->ifa_index);
	fprintf(stderr, "addr_add parameters : %x:%x:%x:%x:%x:%x:%x:%x, %d, %x, %d, %d, 2400000\n",
		NIP6ADDR(addr), ifa->ifa_prefixlen, ifa->ifa_flags | IFA_F_TEMPORARY | IFA_F_TENTATIVE,
		ifa->ifa_scope, ifa->ifa_index);

	return addr_add(addr, ifa->ifa_prefixlen, ifa->ifa_flags | IFA_F_TEMPORARY,
			RT_SCOPE_LINK, ifa->ifa_index, 0, 0);
}

void
trigger_dhcp_configuration(struct md_inet6_iface *iface) {
  struct list_head *l;
  struct dhcp_dna_control_s *dhcp_ctrl = NULL;

  list_for_each(l, &conf.net_ifaces) {
    struct net_iface *ifce;

    ifce = list_entry(l, struct net_iface, list);
    if (ifce->ifindex == iface->ifindex)
      dhcp_ctrl = ifce->dhcp_ctrl;
  }

  if ( (dhcp_ctrl == NULL) || (iface->ifindex != dhcp_ctrl->if_index) ) {
    fprintf(stderr, "dhcp_dna: DHCP not configured to run on interface %d\n",
		iface->ifindex);
    return;
  }

  // Trigger DHCP config if in polling mode
  if (dhcp_ctrl->state == DHCP_POLL) {
    fprintf(stderr, "dhcp_dna: trigger dhcp configuration\n");
    dhcp_ctrl->state = DHCP_INIT_SELECTING;
  }
}

int
dhcp_configuration(struct md_inet6_iface *iface)
{
  int err = 0;
  int if_index = iface->ifindex;
  struct md_router *new;

  unsigned long broadcast;

  unsigned char local_v4_coa[4];// = {192, 168, 0, V4_COA};
  unsigned char brd_v4_coa[4];// = {192, 168, 0, 255};
  struct in_addr rtr_v4_coa;

  struct in6_addr local_v4_coa_v6;

  struct list_head *l;
  struct dhcp_dna_control_s *dhcp_ctrl = NULL;

  list_for_each(l, &conf.net_ifaces) {
    struct net_iface *ifce;

    ifce = list_entry(l, struct net_iface, list);
    if (ifce->ifindex == iface->ifindex)
      dhcp_ctrl = ifce->dhcp_ctrl;
  }

  if (dhcp_ctrl == NULL) {
    fprintf(stderr, "dhcp_dna: interface %d not found in config list\n", iface->ifindex);
    return 0;
  }

  if (dhcp_ctrl->state != DHCP_BOUND) {
    fprintf(stderr, "dhcp_dna: can not configure per request, no v4 address bound\n");
    return 0;
  }

  rtr_v4_coa.s_addr = dhcp_ctrl->gateway;//htonl(0xc0a80000 | V4_RTR);
  struct in_addr addr = { dhcp_ctrl->requested_ip };
  memcpy(local_v4_coa, &dhcp_ctrl->requested_ip, 4);

  broadcast = (dhcp_ctrl->requested_ip & dhcp_ctrl->netmask) | (~dhcp_ctrl->netmask);
  memcpy(brd_v4_coa, &broadcast, 4);

  fprintf(stderr, "dhcp_dna: address information : %d.%d.%d.%d, %d.%d.%d.%d\n",
	  NIP4ADDR(&addr), brd_v4_coa[0], brd_v4_coa[1], brd_v4_coa[2], brd_v4_coa[3] );

  /* later, send DHCP DISCOVER */
  /* for now, we will only statically assign an ipv4 address */

  fprintf(stderr, "dhcp_dna: dhcp configuration triggered for interface %d\n", if_index);
  fprintf(stderr, "dhcp_dna: interface resolved as %s\n", iface->name);

  addr4_add(&addr,24,iface->ifindex);

  new = md_create_router_v4(iface, &rtr_v4_coa);

  memset(&local_v4_coa_v6, 0, sizeof(struct in6_addr));
  local_v4_coa_v6.s6_addr32[2] = htonl (0xffff);
  memcpy(&local_v4_coa_v6.s6_addr32[3], local_v4_coa, 4);

  fprintf(stderr,"adding address %x:%x:%x:%x:%x:%x:%x:%x on interface %d\n", NIP6ADDR(&local_v4_coa_v6), if_index);
  if ((err = addr_do(&local_v4_coa_v6, 128, if_index, NULL, dsmip_v4coa_add)) < 0) {
    fprintf(stderr,"warning : unable to set v4mapped address on interface, error %d\n", err);
  }

  struct in_addr any4 = { 0 };
  struct in_addr gw4 = { dhcp_ctrl->gateway };
  route4_add(if_index, RT6_TABLE_MAIN, NULL, NULL, 0, &any4, 0, &gw4);

  return 1;
}

void
dhcp_link_down(struct md_inet6_iface *iface)
{
  struct request {
    struct nlmsghdr msg;
    struct ifaddrmsg ifa;
    char payload[256];
  } req;

  int err = 0;
  int if_index = iface->ifindex;

  unsigned char local_v4_coa[4];// = {192, 168, 0, V4_COA};
  unsigned char addr_v4_coa[4];// = {192, 168, 0, V4_COA};
  unsigned char brd_v4_coa[4];// = {192, 168, 0, 255};

  struct in6_addr local_v4_coa_v6;

  unsigned long broadcast;

  struct list_head *l;
  struct dhcp_dna_control_s *dhcp_ctrl = NULL;

  list_for_each(l, &conf.net_ifaces) {
    struct net_iface *ifce;

    ifce = list_entry(l, struct net_iface, list);
    if (ifce->ifindex == iface->ifindex)
      dhcp_ctrl = ifce->dhcp_ctrl;
  }

  if (dhcp_ctrl == NULL) {
    fprintf(stderr, "dhcp_dna: interface %d not found in config list\n", iface->ifindex);
    return;
  }

  memcpy(local_v4_coa, &dhcp_ctrl->requested_ip, 4);
  memcpy(addr_v4_coa, &dhcp_ctrl->requested_ip, 4);

  broadcast = (dhcp_ctrl->requested_ip & dhcp_ctrl->netmask) | (~dhcp_ctrl->netmask);
  memcpy(brd_v4_coa, &broadcast, 4);

  fprintf(stderr, "dhcp_dna: address information : %d.%d.%d.%d, %d.%d.%d.%d\n",
	  addr_v4_coa[0], addr_v4_coa[1], addr_v4_coa[2], addr_v4_coa[3],
	  brd_v4_coa[0], brd_v4_coa[1], brd_v4_coa[2], brd_v4_coa[3] );

  /* later, handle DHCP protocol */
  /* for now, we will only statically remove ipv4 address */

  fprintf(stderr, "dhcp_dna: dhcp de-configuration triggered for interface %s(%d)\n", iface->name, if_index);

  memset(&req, 0, sizeof(req));

  req.msg.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.msg.nlmsg_flags = NLM_F_REQUEST;
  req.msg.nlmsg_type = RTM_DELADDR;

  req.ifa.ifa_family = AF_INET;
  req.ifa.ifa_prefixlen = 24;
  req.ifa.ifa_flags = IFA_F_PERMANENT;
  req.ifa.ifa_index = if_index;

  addattr_l(&req.msg, sizeof(req), IFA_LOCAL, &local_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_ADDRESS, &addr_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_BROADCAST, &brd_v4_coa, 4);
  addattr_l(&req.msg, sizeof(req), IFA_LABEL, iface->name, strlen(iface->name) + 1);

  if (rtnl_talk(&dna_rth, &req.msg, 0, 0, NULL, NULL, NULL) < 0)
	fprintf(stderr, "address could not be removed\n");
  else
	fprintf(stderr, "address removed\n");

  memset(&local_v4_coa_v6, 0, sizeof(struct in6_addr));
  local_v4_coa_v6.s6_addr32[2] = htonl (0xffff);
  memcpy(&local_v4_coa_v6.s6_addr32[3], local_v4_coa, 4);

  fprintf(stderr,"removing address %x:%x:%x:%x:%x:%x:%x:%x on interface %d\n", NIP6ADDR(&local_v4_coa_v6), if_index);
  if ((err = addr_del(&local_v4_coa_v6, 128, if_index)) < 0) {
    fprintf(stderr,"warning : unable to remove v4mapped address on interface, error %d\n", err);
  }
}
