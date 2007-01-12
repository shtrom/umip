/*
 * Copyright (C)2004,2005 USAGI/WIDE Project
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * Authors:
 *	Noriaki TAKAMIYA @USAGI
 *	Masahide NAKAMURA @USAGI
 */

/*
 * VT server performs select(2) and only one client access is allowed.
 * To be accept multiple connect, fix "vt_connect_handle".
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#else
#error "POSIX Thread Library required!"
#endif
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <netdb.h>
#include <string.h>
#include <netinet-ip6mh.h>

#include "list.h"
#include "util.h"
#include "debug.h"
#include "conf.h"
#include "vt.h"
#include "bul.h"
#include "bcache.h"
#include "prefix.h"
#include "ha.h"
#include "mn.h"
#include "mpdisc_mn.h"
#include "mpdisc_ha.h"

#define VT_PKT_BUFLEN		(8192)
#define VT_REPLY_BUFLEN		(LINE_MAX)
#define VT_SERVER_BACKLOG	(1)
#define VT_CMD_PROMPT		("mip6d> ")
#define VT_CMD_HELP_STR		("help")
#define VT_CMD_HELP_LINE_MAX	(60)

#define VT_DEBUG_LEVEL 2

#if VT_DEBUG_LEVEL >= 1
#define VTDBG dbg
#else
#define VTDBG(...)
#endif
#if VT_DEBUG_LEVEL >= 2
#define VTDBG2 dbg
#else
#define VTDBG2(...)
#endif
#if VT_DEBUG_LEVEL >= 3
#define VTDBG3 dbg
#else
#define VTDBG3(...)
#endif

struct vt_server_entry {
	struct list_head list;
	int vse_sock;
	union {
		struct sockaddr sa;
		struct sockaddr_storage ss;
	} vse_sockaddr;
	socklen_t vse_sockaddrlen;

#define vse_sa		vse_sockaddr.sa
#define vse_salen	vse_sockaddrlen
};

static pthread_rwlock_t vt_lock;
static pthread_t vt_listener;

static struct vt_cmd_entry vt_cmd_root;

static LIST_HEAD(vt_server_list);
static struct vt_handle *vt_connect_handle = NULL;

static int vt_server_fini(void);
static int vt_connect_close(struct vt_handle *vh);
static int vt_connect_fini(struct vt_handle *vh);

/* Find a handle which is able to be modified */
static struct vt_handle *vt_handle_get(const struct vt_handle *vh)
{
	//assert(vh == vt_connect_handle);
	return vt_connect_handle;
}

static int vt_handle_full(void)
{
	if (vt_connect_handle != NULL)
		return 1;
	else
		return 0;
}

static int vt_handle_add(struct vt_handle *vh)
{
	if (vt_connect_handle != NULL) {
		VTDBG("VT connect handle exists\n");
		return -EINVAL;
	}
	vt_connect_handle = vh;
	return 0;
}

static ssize_t vt_write(int fd, const void *buf, size_t count)
{
	ssize_t nleft;
	ssize_t nwritten;
	const char *p;

	p = buf;
	nleft = count;
	while (nleft > 0) {
		if ((nwritten = write(fd, p, nleft)) <= 0) {
			if (errno == EINTR)
				nwritten = 0;
			else {
				VTDBG("write: %s\n", strerror(errno));
				return -1;
			}
		}
		nleft -= nwritten;
		p += nwritten;
	}
	return count;
}

static ssize_t vt_null_write(int sock)
{
	char c = 0;

	if (sock < 0) {
		VTDBG2("VT not opened socket\n");
		return -EBADFD;
	}

	return vt_write(sock, &c, 1);
}

static ssize_t vt_str_write(int sock, const char *str)
{
	size_t len;

	if (sock < 0) {
		VTDBG2("VT not opened socket\n");
		return -EBADFD;
	}

	len = strlen(str);

	return vt_write(sock, str, len);
}

ssize_t vt_printf(const struct vt_handle *vh, const char *fmt, ...)
{
	char buf[VT_REPLY_BUFLEN];
	va_list ap;

	if (vh == NULL) {
		VTDBG2("VT null handle\n");
		return -EINVAL;
	}

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	return vt_str_write(vh->vh_sock, buf);
}

ssize_t vt_printf_b(const struct vt_handle *vh, const char *fmt, ...)
{
	char buf[VT_REPLY_BUFLEN];
	va_list ap;
	ssize_t ret;

	if (vh == NULL) {
		VTDBG2("VT null handle\n");
		return -EINVAL;
	}

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	if (vh->vh_opt.fancy == VT_BOOL_TRUE)
		vt_str_write(vh->vh_sock, "\033[1m");
	ret = vt_str_write(vh->vh_sock, buf);
	if (vh->vh_opt.fancy == VT_BOOL_TRUE)
		vt_str_write(vh->vh_sock, "\033[0m");

	return ret;
}

ssize_t vt_printf_bl(const struct vt_handle *vh, const char *fmt, ...)
{
	char buf[VT_REPLY_BUFLEN];
	va_list ap;
	ssize_t ret;

	if (vh == NULL) {
		VTDBG2("VT null handle\n");
		return -EINVAL;
	}

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	if (vh->vh_opt.fancy == VT_BOOL_TRUE)
		vt_str_write(vh->vh_sock, "\033[1;4m");
	ret = vt_str_write(vh->vh_sock, buf);
	if (vh->vh_opt.fancy == VT_BOOL_TRUE)
		vt_str_write(vh->vh_sock, "\033[0m");

	return ret;
}

static int vt_cmd_sys_bool_show(const struct vt_handle *vh, vt_bool_t b)
{
	int ret;

	switch (b) {
	case VT_BOOL_TRUE:
		ret = vt_printf(vh, "yes\n");
		break;
	case VT_BOOL_FALSE:
		ret = vt_printf(vh, "no\n");
		break;
	default:
		ret = vt_printf(vh, "%d\n", b);
		break;
	}
	if (ret < 0)
		return ret;
	return 0;
}

static int vt_cmd_sys_fancy_off(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	sysvh->vh_opt.fancy = VT_BOOL_FALSE;
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.fancy);
	return 0;
}

static int vt_cmd_sys_fancy_on(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	sysvh->vh_opt.fancy = VT_BOOL_TRUE;
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.fancy);
	return 0;
}

static int vt_cmd_sys_fancy(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.fancy);
	return 0;
}

static int vt_cmd_sys_verbose_off(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	sysvh->vh_opt.verbose = VT_BOOL_FALSE;
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.verbose);
	return 0;
}

static int vt_cmd_sys_verbose_on(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	sysvh->vh_opt.verbose = VT_BOOL_TRUE;
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.verbose);
	return 0;
}

static int vt_cmd_sys_verbose(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.verbose);
	return 0;
}

static int vt_cmd_sys_prompt_off(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	sysvh->vh_opt.prompt = VT_BOOL_FALSE;
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.prompt);
	return 0;
}

static int vt_cmd_sys_prompt_on(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	sysvh->vh_opt.prompt = VT_BOOL_TRUE;
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.prompt);
	return 0;
}

static int vt_cmd_sys_prompt(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);
	vt_cmd_sys_bool_show(vh, sysvh->vh_opt.prompt);
	return 0;
}

/* for testing */
#include <time.h>
static int vt_cmd_sys_date(const struct vt_handle *vh, const char *str)
{
	struct timespec ts;
	time_t t;
	char strbuf[LINE_MAX];
	int ret;

	if (strlen(str) > 0) {
		int ret = vt_printf(vh, "unknown args\n");
		if (ret < 0)
			return ret;
		return 0;
	}

	memset(&ts, 0, sizeof(ts));
	ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret != 0) {
		VTDBG("clock_gettime: %s\n", strerror(errno));
		return -errno;
	}

	t = (time_t)ts.tv_sec; /* XXX: fix it! */
	if (t == 0) {
		strcpy(strbuf, "(undefined)");
	} else {
		struct tm *tp = localtime(&t);

		sprintf(strbuf, "%04d-%02d-%02d %02d:%02d:%02d",
			tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday,
			tp->tm_hour, tp->tm_min, tp->tm_sec);
	}

	ret = vt_printf(vh, "%s\n", strbuf);
	if (ret < 0)
		return ret;
	return 0;
}

static int vt_cmd_sys_quit(const struct vt_handle *vh, const char *str)
{
	struct vt_handle *sysvh = vt_handle_get(vh);

	if (strlen(str) > 0) {
		int ret = vt_printf(vh, "unknown args\n");
		if (ret < 0)
			return ret;
		return 0;
	}

	vt_connect_close(sysvh);
	return 0;
}

static struct vt_cmd_entry vt_cmd_quit = {
	.cmd = "quit",
	.cmd_alias = "exit",
	.parser = vt_cmd_sys_quit,
};

static struct vt_cmd_entry vt_cmd_date = {
	.cmd = "date",
	.parser = vt_cmd_sys_date,
};

static struct vt_cmd_entry vt_cmd_prompt = {
	.cmd = "prompt",
	.parser = vt_cmd_sys_prompt,
};

static struct vt_cmd_entry vt_cmd_prompt_on = {
	.cmd = "yes",
	.cmd_alias = "y",
	.parser = vt_cmd_sys_prompt_on,
};

static struct vt_cmd_entry vt_cmd_prompt_off = {
	.cmd = "no",
	.cmd_alias = "n",
	.parser = vt_cmd_sys_prompt_off,
};

static struct vt_cmd_entry vt_cmd_verbose = {
	.cmd = "verbose",
	.parser = vt_cmd_sys_verbose,
};

static struct vt_cmd_entry vt_cmd_verbose_on = {
	.cmd = "yes",
	.cmd_alias = "y",
	.parser = vt_cmd_sys_verbose_on,
};

static struct vt_cmd_entry vt_cmd_verbose_off = {
	.cmd = "no",
	.cmd_alias = "n",
	.parser = vt_cmd_sys_verbose_off,
};

static struct vt_cmd_entry vt_cmd_fancy = {
	.cmd = "fancy",
	.parser = vt_cmd_sys_fancy,
};

static struct vt_cmd_entry vt_cmd_fancy_on = {
	.cmd = "yes",
	.cmd_alias = "y",
	.parser = vt_cmd_sys_fancy_on,
};

static struct vt_cmd_entry vt_cmd_fancy_off = {
	.cmd = "no",
	.cmd_alias = "n",
	.parser = vt_cmd_sys_fancy_off,
};

static int vt_cmd_sys_init(void)
{
	int ret;

	vt_cmd_init(&vt_cmd_quit);
	ret = vt_cmd_add_root(&vt_cmd_quit);
	if (ret < 0)
		return ret;

	vt_cmd_init(&vt_cmd_date);
	ret = vt_cmd_add_root(&vt_cmd_date);
	if (ret < 0)
		return ret;

	vt_cmd_init(&vt_cmd_prompt);
	ret = vt_cmd_add_root(&vt_cmd_prompt);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_prompt_on);
	ret = vt_cmd_add(&vt_cmd_prompt, &vt_cmd_prompt_on);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_prompt_off);
	ret = vt_cmd_add(&vt_cmd_prompt, &vt_cmd_prompt_off);
	if (ret < 0)
		return ret;

	vt_cmd_init(&vt_cmd_verbose);
	ret = vt_cmd_add_root(&vt_cmd_verbose);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_verbose_on);
	ret = vt_cmd_add(&vt_cmd_verbose, &vt_cmd_verbose_on);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_verbose_off);
	ret = vt_cmd_add(&vt_cmd_verbose, &vt_cmd_verbose_off);
	if (ret < 0)
		return ret;

	vt_cmd_init(&vt_cmd_fancy);
	ret = vt_cmd_add_root(&vt_cmd_fancy);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_fancy_on);
	ret = vt_cmd_add(&vt_cmd_fancy, &vt_cmd_fancy_on);
	if (ret < 0)
		return ret;
	vt_cmd_init(&vt_cmd_fancy_off);
	ret = vt_cmd_add(&vt_cmd_fancy, &vt_cmd_fancy_off);
	if (ret < 0)
		return ret;

	return 0;
}

static int vt_cmd_dump_candidates(const struct vt_handle *vh,
				  const struct vt_cmd_entry *ent, int line_max)
{
	const char sep[] = " ";
	const int seplen = strlen(sep);
	int llen = 0;
	int n = 0;
	int ret;
	struct list_head *lp;

	list_for_each (lp, &ent->child_list) {
		const struct vt_cmd_entry *e;
		int cmdlen;

		e = list_entry(lp, const struct vt_cmd_entry, list);

		if (!e->cmd)
			continue;

		cmdlen = strlen(e->cmd);

		/* check whether new-line is needed or not */
		if (n > 0) {
			if (llen + seplen + cmdlen >= line_max) {
				ret = vt_printf(vh, "\n");
				llen = 0;
			} else {
				/* add a separator */
				ret = vt_printf(vh, sep);
				llen += seplen;
			}
			if (ret < 0)
				return ret;
		}
		llen += cmdlen;

		ret = vt_printf(vh, e->cmd);
		if (ret < 0)
			return ret;

		n++;
	}

	ret = vt_printf(vh, "\n");
	if (ret < 0)
		return ret;

	return 0;
}


struct bul_vt_arg {
	const struct vt_handle *vh;
	int is_bul;
	int is_hot;
	int is_cot;
	int is_ncn;
};

static int bul_vt_dump(void *data, void *arg)
{
	struct bulentry *bule = (struct bulentry *)data;
	struct bul_vt_arg *bva = (struct bul_vt_arg *)arg;
	const struct vt_handle *vh = bva->vh;
	int is_reg = 0;
	int is_rr = 0;
	struct timespec ts_now;
	int ts_now_broken = 0;

	if ((bule->type == BUL_ENTRY && !bva->is_bul) ||
	    (bule->type == HOT_ENTRY && !bva->is_hot) ||
	    (bule->type == COT_ENTRY && !bva->is_cot) ||
	    (bule->type == NON_MIP_CN_ENTRY && !bva->is_ncn))
		return 0;

	is_reg = (bule->type == BUL_ENTRY) && (bule->flags & IP6_MH_BU_HOME);
	is_rr = (bule->type == HOT_ENTRY) || (bule->type == COT_ENTRY);

	vt_printf_bl(vh, "%s %x:%x:%x:%x:%x:%x:%x:%x",
		     (is_reg ? "ha" :
		      (bule->type == NON_MIP_CN_ENTRY) ? "non-cn" : "cn"),
		     NIP6ADDR(&bule->peer_addr));

	switch (bule->type) {
	case BUL_ENTRY:
		vt_printf(vh, " ack %s", bule->wait_ack ? "wait" : "ready");
		break;
	case HOT_ENTRY:
		vt_printf(vh, " hot %s", bule->rr.wait_hot ? "wait" : "ready");
		break;
	case COT_ENTRY:
		vt_printf(vh, " cot %s", bule->rr.wait_cot ? "wait" : "ready");
		break;
	case NON_MIP_CN_ENTRY:
		break;
	default:
		vt_printf(vh, " (unknown type %d)", bule->type);
		break;
	}

	vt_printf(vh, "\n");

	if (bule->type != NON_MIP_CN_ENTRY) {
		vt_printf_b(vh, " coa %x:%x:%x:%x:%x:%x:%x:%x",
			    NIP6ADDR(&bule->coa));

		if (vh->vh_opt.verbose == VT_BOOL_TRUE) {
			char buf[IF_NAMESIZE + 1];
			char *dev = if_indextoname(bule->if_coa, buf);

			vt_printf(vh, " dev ");

			if (!dev || strlen(dev) == 0)
				vt_printf(vh, "(%d)", bule->if_coa);
			else
				vt_printf(vh, "%s", dev);
		}

		if (!is_reg) {
			if (vh->vh_opt.verbose == VT_BOOL_TRUE)
				vt_printf(vh, " nonce %u", bule->rr.coa_nonce_ind);
		}

		if (!is_rr) {
			int i;
			uint16_t f = 0;
			vt_printf(vh, " flags %c%c%c%c",
				  ((bule->flags & IP6_MH_BU_ACK) ? 'A' : '-'),
				  ((bule->flags & IP6_MH_BU_HOME) ? 'H' : '-'),
				  ((bule->flags & IP6_MH_BU_LLOCAL) ? 'L' : '-'),
				  ((bule->flags & IP6_MH_BU_KEYM) ? 'K' : '-'));

			for (i = 0; i < sizeof(bule->flags); i++) {
				f = 1 << i;
				if (bule->flags & f)
					vt_printf(vh, "%c", 1);
			}

//			if (vh->vh_opt.verbose == VT_BOOL_TRUE)
//				vt_printf(vh, "(%x)", bule->flags);
		}
		vt_printf(vh, "\n");
	}

	if (bule->type == BUL_ENTRY) {
		if (vh->vh_opt.verbose == VT_BOOL_TRUE) {
			vt_printf(vh, "   prev-coa %x:%x:%x:%x:%x:%x:%x:%x",
				  NIP6ADDR(&bule->prev_coa));
			vt_printf(vh, "\n");
		}
	}

	if (bule->type != COT_ENTRY) {
		if (bule->type == HOT_ENTRY ||
		    vh->vh_opt.verbose == VT_BOOL_TRUE) {
			vt_printf(vh, " hoa %x:%x:%x:%x:%x:%x:%x:%x",
				  NIP6ADDR(&bule->hoa));

			if (!is_reg) {
				if (vh->vh_opt.verbose == VT_BOOL_TRUE)
					vt_printf(vh, " nonce %u",
						  bule->rr.home_nonce_ind);
			}

			vt_printf(vh, "\n");
		}
	}

	if (clock_gettime(CLOCK_REALTIME, &ts_now) != 0)
		ts_now_broken = 1;

	vt_printf(vh, " lifetime ");
	if (!ts_now_broken) {
		if (tsafter(ts_now, bule->lastsent))
			vt_printf(vh, "(broken)");
		else {
			struct timespec ts;

			tssub(ts_now, bule->lastsent, ts);
			/* "ts" is now time how log it goes */
			if (tsafter(bule->lifetime, ts)) {
				tssub(ts, bule->lifetime, ts);
				vt_printf(vh, "-%lu", ts.tv_sec);
			} else {
				tssub(bule->lifetime, ts, ts);
				vt_printf(vh, "%lu", ts.tv_sec);
			}
		}
	} else
		vt_printf(vh, "(error)");
	vt_printf(vh, " / %lu", bule->lifetime.tv_sec);

	if (!is_rr)
		vt_printf(vh, " seq %u", bule->seq);
  	vt_printf(vh, " resend %d", bule->consecutive_resends);
	vt_printf(vh, " delay %u after %d", 
		  bule->delay.tv_sec,
		  bule->lastsent.tv_sec + bule->delay.tv_sec - ts_now.tv_sec);
	if (tsisset(bule->rr.kgen_expires) && bule->type != COT_ENTRY )
		vt_printf(vh, " homekey %d / %d",
			  bule->rr.kgen_expires.tv_sec - ts_now.tv_sec,
			  MAX_TOKEN_LIFETIME);

	if (vh->vh_opt.verbose == VT_BOOL_TRUE) {
		vt_printf(vh, " expires ");
		if (tsisset(bule->expires)) {
			if (!ts_now_broken) {
				struct timespec ts;

				if (tsafter(bule->expires, ts_now)) {
					tssub(ts_now, bule->expires, ts);
					vt_printf(vh, "-%lu", ts.tv_sec);
				} else {
					tssub(bule->expires, ts_now, ts);
					vt_printf(vh, "%lu", ts.tv_sec);
				}
			} else
				vt_printf(vh, "(error)");
		} else
			vt_printf(vh, "-");
	}

	vt_printf(vh, "\n");

	if (is_reg && !is_rr && !ts_now_broken) {
		struct timespec delay, lastsent, expires;
		if (!mpd_poll_mps(&bule->hoa,
				  &bule->peer_addr, &delay, &lastsent,
				  &expires)) {
			vt_printf(vh, " mps ");
			if (tsafter(ts_now, lastsent))
				vt_printf(vh, "(broken)");
			else {
				struct timespec ts;
				if (tsisset(lastsent)) {
					tssub(ts_now, lastsent, ts);
					/* "ts" is now time how log it goes */
					if (tsafter(delay, ts)) {
						tssub(ts, delay, ts);
						vt_printf(vh, "-%lu", ts.tv_sec);
					} else {
						tssub(delay, ts, ts);
						vt_printf(vh, "%lu", ts.tv_sec);
					}
				} else {
					/* The case we have never send any MPS... */
					tssub(expires, ts_now, ts);
					if (tsafter(delay, ts)) {
						tssub(ts, delay, ts);
						vt_printf(vh, "-%lu", ts.tv_sec);
					} else {
						vt_printf(vh, "%lu", ts.tv_sec);
					}
				}

			}
			vt_printf(vh, " / %lu", delay.tv_sec);
		}
	}

	if (!is_rr && vh->vh_opt.verbose == VT_BOOL_TRUE) {
		vt_printf(vh, " kgen ");
		if (tsisset(bule->rr.kgen_expires)) {
			if (!ts_now_broken) {
				struct timespec ts;

				if (tsafter(bule->rr.kgen_expires, ts_now)) {
					tssub(ts_now, bule->rr.kgen_expires, ts);
					vt_printf(vh, "-%lu", ts.tv_sec);
				} else {
					tssub(bule->rr.kgen_expires, ts_now, ts);
					vt_printf(vh, "%lu", ts.tv_sec);
				}
			} else
				vt_printf(vh, "(error)");
		} else
			vt_printf(vh, "-");
	}

	vt_printf(vh, "\n");

	return 0;
}

static int bul_vt_cmd_bul(const struct vt_handle *vh, const char *str)
{
	struct bul_vt_arg bva;
	memset(&bva, 0, sizeof(bva));
	bva.vh = vh;
	bva.is_bul = 1;

	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}
	pthread_rwlock_rdlock(&mn_lock);
	bul_iterate(NULL, bul_vt_dump, &bva);
	pthread_rwlock_unlock(&mn_lock);
	return 0;
}

static int bul_vt_cmd_rr(const struct vt_handle *vh, const char *str)
{
	struct bul_vt_arg bva;
	memset(&bva, 0, sizeof(bva));
	bva.vh = vh;
	bva.is_hot = 1;
	bva.is_cot = 1;

	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}

	bul_iterate(NULL, bul_vt_dump, &bva);
	return 0;
}

static int bul_vt_cmd_ncn(const struct vt_handle *vh, const char *str)
{
	struct bul_vt_arg bva;
	memset(&bva, 0, sizeof(bva));
	bva.vh = vh;
	bva.is_ncn = 1;

	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}
	pthread_rwlock_rdlock(&mn_lock);
	bul_iterate(NULL, bul_vt_dump, &bva);
	pthread_rwlock_unlock(&mn_lock);
	return 0;
}

static struct vt_cmd_entry vt_cmd_bul = {
	.cmd = "bul",
	.parser = bul_vt_cmd_bul,
};

static struct vt_cmd_entry vt_cmd_rr = {
	.cmd = "rr",
	.parser = bul_vt_cmd_rr,
};

static struct vt_cmd_entry vt_cmd_ncn = {
	.cmd = "ncn",
	.cmd_alias = "non-cn",
	.parser = bul_vt_cmd_ncn,
};

struct bcache_vt_arg {
	const struct vt_handle *vh;
	int is_nb;
};

static int bcache_vt_dump(void *data, void *arg)
{
	struct bcentry *bce = (struct bcentry *)data;
	struct bcache_vt_arg *bva = (struct bcache_vt_arg *)arg;
	const struct vt_handle *vh = bva->vh;
	int is_nb = bva->is_nb;
	struct timespec ts_now;

	if (is_nb) {
		if (bce->type != BCE_NONCE_BLOCK)
			return 0;
	} else {
		if (bce->type == BCE_NONCE_BLOCK)
			return 0;
	}

	tsclear(ts_now);

	vt_printf_bl(vh, "hoa %x:%x:%x:%x:%x:%x:%x:%x",
		     NIP6ADDR(&bce->peer_addr));

	if (vh->vh_opt.verbose == VT_BOOL_TRUE)
		vt_printf(vh, " nonce %u", bce->nonce_hoa);

	vt_printf_b(vh, " status %s",
		    (bce->type == BCE_HOMEREG) ? "registered" :
		    (bce->type == BCE_CACHED) ? "cached" :
		    (bce->type == BCE_NONCE_BLOCK) ? "nonce-block" :
		    (bce->type == BCE_CACHE_DYING) ? "dying" :
		    (bce->type == BCE_DAD) ? "dad" :
		    "(unknown)");

	vt_printf(vh, "\n");

	vt_printf(vh, " coa %x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(&bce->coa));

	if (vh->vh_opt.verbose == VT_BOOL_TRUE)
		vt_printf(vh, " nonce %u", bce->nonce_coa);

	vt_printf(vh, " flags %c%c%c%c",
		  ((bce->flags & IP6_MH_BU_ACK) ? 'A' : '-'),
		  ((bce->flags & IP6_MH_BU_HOME) ? 'H' : '-'),
		  ((bce->flags & IP6_MH_BU_LLOCAL) ? 'L' : '-'),
		  ((bce->flags & IP6_MH_BU_KEYM) ? 'K' : '-'));
	if (vh->vh_opt.verbose == VT_BOOL_TRUE)
		vt_printf(vh, "(%x)", bce->flags);

	vt_printf(vh, "\n");

	vt_printf(vh, " local %x:%x:%x:%x:%x:%x:%x:%x", NIP6ADDR(&bce->our_addr));

	if (vh->vh_opt.verbose == VT_BOOL_TRUE) {
		char buf[IF_NAMESIZE + 1];
		char *dev;

		if (bce->tunnel) {
			vt_printf(vh, " tunnel ");

			dev = if_indextoname(bce->tunnel, buf);
			if (!dev || strlen(dev) == 0)
				vt_printf(vh, "(%d)", bce->tunnel);
			else
				vt_printf(vh, "%s", dev);
		}
		if (bce->link) {
			vt_printf(vh, " link ");

			dev = if_indextoname(bce->link, buf);
			if (!dev || strlen(dev) == 0)
				vt_printf(vh, "(%d)", bce->link);
			else
				vt_printf(vh, "%s", dev);
		}
	}

	vt_printf(vh, "\n");

	vt_printf(vh, " lifetime ");
	if (bce->type == BCE_DAD)
		vt_printf(vh, "-");
	else if (clock_gettime(CLOCK_REALTIME, &ts_now) != 0)
		vt_printf(vh, "(error)");
	else {
		if (tsafter(ts_now, bce->add_time))
			vt_printf(vh, "(broken)");
		else {
			struct timespec ts;

			tssub(ts_now, bce->add_time, ts);
			/* "ts" is now time how log it alives */
			if (tsafter(bce->lifetime, ts)) {
				tssub(ts, bce->lifetime, ts);
				vt_printf(vh, "-%lu", ts.tv_sec);
			} else {
				tssub(bce->lifetime, ts, ts);
				vt_printf(vh, "%lu", ts.tv_sec);
			}
		}
	}
	vt_printf(vh, " / %lu", bce->lifetime.tv_sec);

	vt_printf(vh, " seq %u", bce->seqno);

	vt_printf(vh, " unreach %d", bce->unreach);

	if ((bce->flags & IP6_MH_BU_HOME) && tsisset(ts_now)) {
		struct timespec delay, lastsent;
		int retries = mpd_poll_mpa(&bce->our_addr, &bce->peer_addr,
					   &delay, &lastsent);
		if (retries >= 0) {
			vt_printf(vh, " mpa ");
			if (!tsisset(lastsent))
				vt_printf(vh, "-");
			else if (tsafter(ts_now, lastsent))
				vt_printf(vh, "(broken)");
			else {
				struct timespec ts;

				tssub(ts_now, lastsent, ts);
				/* "ts" is now time how log it alives */
				if (tsafter(delay, ts)) {
					tssub(ts, delay, ts);
					vt_printf(vh, "-%lu", ts.tv_sec);
				} else {
					tssub(delay, ts, ts);
					vt_printf(vh, "%lu", ts.tv_sec);
				}
			}
		}
		vt_printf(vh, " / %lu", delay.tv_sec);
		vt_printf(vh, " retry %d", retries);
	}

	vt_printf(vh, "\n");

	return 0;
}

static int bcache_vt_cmd_bc(const struct vt_handle *vh, const char *str)
{
	struct bcache_vt_arg bva;
	bva.vh = vh;
	bva.is_nb = 0;

	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}

	bcache_iterate(bcache_vt_dump, &bva);
	return 0;
}

static int bcache_vt_cmd_nonce(const struct vt_handle *vh, const char *str)
{
	struct bcache_vt_arg bva;
	bva.vh = vh;
	bva.is_nb = 1;

	if (strlen(str) > 0) {
		vt_printf(vh, "unknown args\n");
		return 0;
	}

	bcache_iterate(bcache_vt_dump, &bva);
	return 0;
}

static struct vt_cmd_entry vt_cmd_bc = {
	.cmd = "bc",
	.parser = bcache_vt_cmd_bc,
};

static struct vt_cmd_entry vt_cmd_nonce = {
	.cmd = "nonce",
	.parser = bcache_vt_cmd_nonce,
};

int vt_cmd_add(struct vt_cmd_entry *parent, struct vt_cmd_entry *e)
{
	int err = 0;
	struct list_head *lp;

	pthread_rwlock_wrlock(&vt_lock);

	if (!parent || !e) {
		err = -EINVAL;
		goto fin;
	}
	if (e == &vt_cmd_root) {
		VTDBG("VT table failed: root must not be a child: \"%s\"\n",
		      parent->cmd);
		err = -EINVAL;
		goto fin;
	}
	if (parent != &vt_cmd_root && parent->parent == NULL) {
		VTDBG("VT table failed: parent is not on root: \"%s\"\n",
		      parent->cmd);
		err = -EINVAL;
		goto fin;
	}
	if (e->parent != NULL) {
		VTDBG("VT table failed: already added: \"%s\"\n", e->cmd);
		err = -EINVAL;
		goto fin;
	}

	/* insert the entry to the list */
	/* XXX: TODO: it should be checked infinite loop */
	list_for_each (lp, &parent->child_list) {
		struct vt_cmd_entry *ce;
		ce = list_entry(lp, struct vt_cmd_entry, list);
		if (strcmp(ce->cmd, e->cmd) > 0) {
			list_add_tail(&e->list, lp);
			goto inserted;
		}
	}

	list_add_tail(&e->list, &parent->child_list);

 inserted:
	e->parent = parent;

 fin:
	pthread_rwlock_unlock(&vt_lock);

	return err;
}

int vt_cmd_add_root(struct vt_cmd_entry *e)
{
	return vt_cmd_add(&vt_cmd_root, e);
}

int vt_cmd_init(struct vt_cmd_entry *e)
{
	INIT_LIST_HEAD(&e->list);
	e->parent = NULL;
	INIT_LIST_HEAD(&e->child_list);
	return 0;
}

static int vt_cmd_has_child(struct vt_cmd_entry *e)
{
	return !list_empty(&e->child_list);
}

static const char *vt_str_nonspace_skip(const char *str)
{
	int len = strlen(str);
	int i = 0;

	for (i = 0; i < len; i++) {
		if (isspace(str[i]) != 0)
			break;
	}

	return &str[i];
}

static const char *vt_str_space_skip(const char *str)
{
	int len = strlen(str);
	int i = 0;

	for (i = 0; i < len; i++) {
		if (isspace(str[i]) == 0)
			break;
	}

	return &str[i];
}

static int vt_str_match(const char *def, const char *str)
{
	int def_len = strlen(def);
	int len = strlen(str);

	if (def_len == len) {
		if (strncmp(def, str, def_len) == 0)
			return 1;
	} else if (def_len < len) {
		if (strncmp(def, str, def_len) == 0 &&
		    isspace(str[def_len]) != 0)
			return 1;
	}
	return 0;
}

static int vt_cmd_match(struct vt_cmd_entry *e, const char *cmd)
{
	return (vt_str_match(e->cmd, cmd) ||
		(e->cmd_alias && vt_str_match(e->cmd_alias, cmd)));
}

/*
 * It is only used the parser which is the final level away from root.
 */
static int vt_cmd_input(const struct vt_handle *vh, char *line, ssize_t len)
{
	struct vt_cmd_entry *ce = &vt_cmd_root;
	const char *p;
	int ret;

	pthread_rwlock_rdlock(&vt_lock);
	p = line;

	while (1) {
		const char *p_next = NULL;
		struct vt_cmd_entry *e = NULL;
		struct list_head *lp;

		p = vt_str_space_skip(p);
		/* command has no character */
		if (strlen(p) == 0) {
			VTDBG3("VT cmd = (no char)\n");
			goto fin;
		}

		list_for_each (lp, &ce->child_list) {
			e = list_entry(lp, struct vt_cmd_entry, list);

			if (vt_cmd_match(e, p) == 0)
				continue;
			VTDBG3("VT cmd = \"%s\"\n", e->cmd);

			//p_next = p + strlen(e->cmd);
			p_next = vt_str_nonspace_skip(p);
			p_next = vt_str_space_skip(p_next);
			VTDBG3("VT p next = \"%s\"\n", p_next);

			if (strlen(p_next) > 0 && vt_cmd_has_child(e))
				break;

			if (!e->parser) {
				vt_printf(vh, "do nothing\n");
				goto fin;
			}

			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			ret = e->parser(vh, p_next);
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			if (ret != 0) {
				VTDBG3("command parse failed\n");
				vt_printf(vh, "command parse failed\n");
			}

			goto fin;
		}

		if (p_next) {
			p = p_next;
			ce = e;
		} else if (vt_str_match(VT_CMD_HELP_STR, p)) {
			/* try to show help message when no matching command */
			vt_cmd_dump_candidates(vh, ce, VT_CMD_HELP_LINE_MAX);
			goto fin;
		} else {
			vt_printf(vh, "unknown command: \"%s\"\n", p);
			goto fin;
		}
	}

 fin:
	if (vh->vh_sock < 0) {
		/* socket is closed during paring (normal operation) */
		goto closed;
	}

	if (vh->vh_opt.prompt == VT_BOOL_TRUE) {
		/* send prompt */
		vt_printf(vh, VT_CMD_PROMPT);
	}

	vt_null_write(vh->vh_sock);

	pthread_rwlock_unlock(&vt_lock);

	return 0;

 closed:
	pthread_rwlock_unlock(&vt_lock);

	return 1;

}

static int vt_connect_input(struct vt_handle *vh, void *data, ssize_t len)
{
	char *line = NULL;
	int i;
	int j;
	int ret;

	//assert(len != 0 && data != NULL);

	line = (char *)malloc(len);
	if (!line) {
		VTDBG("malloc: %s\n", strerror(errno));
		ret = -errno;
		goto fin;
	}
	memset(line, '\0', len);
	memcpy(line, data, len);
#ifdef VTDBG3
	{
		int slen = len * 5;
		char *s = (char *)malloc(slen);
		if (s) {
			memset(s, '\0', slen);

			for (i = 0; i < len; i++) {
				char buf[5];
				char c = line[i];
				if (isprint(c) == 0)
					sprintf(buf, "[%d]", c);
				else
					sprintf(buf, "%c", c);
				strcat(s, buf);
			}
			VTDBG3("line = \"%s\"\n", s);
		}
	}
#endif

	for (i = 0; i < len; i++) {
		for (j = i; j < len; j++) {
			if (line[j] == ' ' || isspace(line[j]) == 0)
				continue;
			else {
				line[j] = '\0';
				break;
			}
		}

		ret = vt_cmd_input(vh, &line[i], j - i);
		if (ret != 0)
			goto fin;

		for (j = j + 1; j < len; j++) {
			if (line[j] == ' ' || isspace(line[j]) == 0)
				break;
		}

		i = j - 1;
	}

	free(line);
	return 0;

 fin:
	if (line)
		free(line);

	vt_connect_close(vh);
	return ret;
}

static int vt_connect_recv(struct vt_handle *vh)
{
	VTDBG3("VT processing\n");

	while (1) {
		char buf[VT_PKT_BUFLEN];
		struct msghdr msg;
		struct iovec iov = { buf, sizeof(buf) };
		ssize_t len;
		int ret;

		memset(buf, 0, sizeof(buf));
		memset(&msg, 0, sizeof(msg));

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;

		if (vh->vh_sock < 0) {
			VTDBG("VT not opened socket\n");
			return -EBADFD;
		}

		ret = recvmsg(vh->vh_sock, &msg, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			VTDBG("recvmsg: %s\n", strerror(errno));
			return -1;
		} else if (ret == 0) {
			VTDBG("client disconnect\n");
			goto disconnect;
		}
		len = ret;

		ret = vt_connect_input(vh, buf, len);
		if (ret != 0)
			goto disconnect;

		if (msg.msg_flags & MSG_TRUNC) {
			VTDBG2("recvmsg: message truncated: datagram\n");
			continue;
		}
		if (msg.msg_flags & MSG_CTRUNC) {
			VTDBG2("recvmsg: message truncated: ancillary data\n");
			continue;
		}

		break;
	}

	return 0;

 disconnect:
	vt_connect_close(vh);
	return 1;
}

static int vt_connect_close(struct vt_handle *vh)
{
	if (vh->vh_sock < 0)
		return 0;

	close(vh->vh_sock);
	VTDBG2("VT connect closed\n");

	vh->vh_sock = -1;

	return 0;
}

static int vt_connect_fini(struct vt_handle *vh)
{
	//assert(vh == vt_connect_handle);

	if (vh->vh_sock >= 0)
		vt_connect_close(vh);

	memset(vh, 0, sizeof(*vh)); /* for fail-safe */
	vh->vh_sock = -1;

	free(vh);

	vt_connect_handle = NULL; /* XXX: remove from global pointer */

	return 0;
}

static int vt_connect_init(const struct vt_server_entry *vse)
{
	int sock;
	struct vt_handle *vh = NULL;
	int ret;

	sock = accept(vse->vse_sock, NULL, NULL);
	if (sock < 0) {
		VTDBG("accept: %s\n", strerror(errno));
		goto error;
	}
	VTDBG2("VT connect accepted\n");

	if (vt_handle_full()) {
		VTDBG("VT connect is too many, reject new one\n");

		/* send error mesasge */
		ret = vt_str_write(sock, "Too many connections\n");
		if (ret < 0) {
			VTDBG2("VT write failed for rejecting connection\n");
			/* ignore error here*/
		}
		close(sock);
		goto error;
	}

	vh = (struct vt_handle *)malloc(sizeof(*vh));
	if (vh == NULL) {
		VTDBG("malloc: %s\n", strerror(errno));
		ret = -errno;

		/* send error mesasge */
		if (vt_str_write(sock, "Server cannot make connection\n") < 0) {
			VTDBG2("VT write failed for connection failure\n");
			/* ignore error here*/
		}
		close(sock);
		goto error;
	}
	memset(vh, 0, sizeof(*vh));

	vh->vh_sock = sock;

	/* Apply default values to option per server */
	switch (vse->vse_sa.sa_family) {
	case AF_LOCAL:
		vh->vh_opt.prompt = VT_BOOL_FALSE;
		vh->vh_opt.verbose = VT_BOOL_FALSE;
		vh->vh_opt.fancy = VT_BOOL_FALSE;
		break;
	default:
		vh->vh_opt.prompt = VT_BOOL_TRUE;
		vh->vh_opt.verbose = VT_BOOL_FALSE;
		vh->vh_opt.fancy = VT_BOOL_TRUE;
		break;
	}

	ret = vt_handle_add(vh);
	if (ret != 0) {
		VTDBG("VT cannot add new handle\n");
		goto error;
	}

	if (vh->vh_opt.prompt == VT_BOOL_TRUE) {
		/* send prompt */
		ret = vt_printf(vh, VT_CMD_PROMPT);
		if (ret < 0)
			goto error;
	}

	return 0;

 error:
	if (vh)
		vt_connect_fini(vh);

	return 0; /* ignore error here */
}

void *vt_server_recv(void *arg)
{
	while (1) {
		int ret;
		int sock_max = 0;
		fd_set fds;
		struct list_head *lp;

		FD_ZERO(&fds);
		list_for_each (lp, &vt_server_list) {
			struct vt_server_entry *e;
			e = list_entry(lp, struct vt_server_entry, list);
			FD_SET(e->vse_sock, &fds);

			if (sock_max < e->vse_sock)
				sock_max = e->vse_sock;
			VTDBG3("VT select server sock = %d\n", e->vse_sock);
		}
		if (sock_max == 0)
			break;
		if (vt_connect_handle != NULL &&
		    vt_connect_handle->vh_sock >= 0) {
			FD_SET(vt_connect_handle->vh_sock, &fds);
			if (sock_max < vt_connect_handle->vh_sock)
				sock_max = vt_connect_handle->vh_sock;
			VTDBG3("VT select connect sock = %d\n",
			       vt_connect_handle->vh_sock);
		}

		VTDBG3("VT server selecting\n");

		ret = select(sock_max+1, &fds, NULL, NULL, NULL); 
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			VTDBG("select: %s\n", strerror(errno));
			break;
		}

		VTDBG3("VT server select\n");

		ret = 0;
		list_for_each (lp, &vt_server_list) {
			struct vt_server_entry *e;
			e = list_entry(lp, struct vt_server_entry, list);

			if (FD_ISSET(e->vse_sock, &fds)) {
				VTDBG3("VT server select sock = %d\n",
				       e->vse_sock);
				ret = vt_connect_init(e);
				if (ret != 0)
					break;
			}
		}
		if (ret != 0)
			break;

		if (vt_connect_handle != NULL &&
		    vt_connect_handle->vh_sock >= 0) {
			if (FD_ISSET(vt_connect_handle->vh_sock, &fds)) {
				VTDBG3("VT server select sock = %d\n",
				       vt_connect_handle->vh_sock);

				ret = vt_connect_recv(vt_connect_handle);
				if (ret != 0)
					vt_connect_fini(vt_connect_handle);
			}
		}
	}

	VTDBG("VT server shutdown\n");
	if (vt_connect_handle != NULL)
		vt_connect_fini(vt_connect_handle);
	vt_server_fini();

	return NULL;
}

static int vt_server_clean(const struct sockaddr *sa, int salen)
{
	if (sa->sa_family == AF_LOCAL) {
		const struct sockaddr_un *sun;
		if (salen >= sizeof(*sun)) {
			sun = (const struct sockaddr_un *)sa;
			if (unlink(sun->sun_path))
				errno = 0; /* ignore error here */
		}
	}

	return 0;
}

static void vt_server_close(struct vt_server_entry *e)
{
	if (e->vse_sock) {
		close(e->vse_sock);
		e->vse_sock = -1;
	}
}


static int vt_server_fini(void)
{
	struct list_head *lp, *tmp;

	list_for_each_safe (lp, tmp,  &vt_server_list) {
		struct vt_server_entry *e;

		list_del(lp);
		e = list_entry(lp, struct vt_server_entry, list);

		if (e->vse_sock >= 0)
			vt_server_clean(&e->vse_sa, e->vse_salen);
		vt_server_close(e);
		memset(e, 0, sizeof(*e)); /* for fail-safe */
		free(e);
	}

	VTDBG2("VT server closed\n");
	return 0;
}

static int vt_server_setsockopt(int sock, struct addrinfo *ai)
{
	int ret;

	ret = vt_server_clean(ai->ai_addr, ai->ai_addrlen);
	if (ret != 0)
		return ret;

	if (ai->ai_protocol == IPPROTO_TCP) {
		const int on = 1;

		ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				 &on, sizeof(on));
		if (ret != 0) {
			VTDBG("setsockopt(SO_REUSEADDR): %s\n",
			      strerror(errno));
			return ret;
		}
	}
	return 0;
}

static int vt_server_init(const char *node, const char *service,
			  struct addrinfo *hints)
{
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	int ret;
	int n = 0;

	ret = getaddrinfo(node, service, hints, &res);
	if (ret != 0) {
		VTDBG("getaddrinfo: %s(%d)\n", gai_strerror(ret), ret);
		goto error;
	}
	errno = 0;

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		int sock;
		struct vt_server_entry *e;

		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			continue;

		ret = vt_server_setsockopt(sock, ai);
		if (ret != 0) {
			close(sock);
			continue;
		}

		ret = bind(sock, ai->ai_addr, ai->ai_addrlen);
		if (ret != 0) {
			VTDBG("bind: %s\n", strerror(errno));
			close(sock);
			continue;
		}

		ret = listen(sock, VT_SERVER_BACKLOG);
		if (ret != 0) {
			VTDBG("listen: %s\n", strerror(errno));
			close(sock);
			continue;
		}

		e = (struct vt_server_entry *)malloc(sizeof(*e));
		if (e == NULL) {
			VTDBG("malloc: %s\n", strerror(errno));
			ret = -errno;
			close(sock);
			goto error;
		}
		memset(e, 0, sizeof(*e));
		e->vse_sock = sock;
		memcpy(&e->vse_sa, ai->ai_addr, ai->ai_addrlen);
		e->vse_salen = ai->ai_addrlen;

		list_add(&e->list, &vt_server_list);

#ifdef VTDBG2
		{
			char hbuf[256];
			char sbuf[32];
			if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
					hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
					(NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
				VTDBG2("VT server listens %s[%s] OK\n", hbuf,
				       sbuf);
		}
#endif

		n ++;
	}
	if (n == 0) {
		ret = -1;
		VTDBG("VT no server sockets can open\n");
		goto error;
	}
	errno = 0;

	if (res != NULL)
		freeaddrinfo(res);

	return 0;
 error:
	VTDBG("VT server init NG\n");
	if (res != NULL)
		freeaddrinfo(res);
	vt_server_fini();
	return ret;
}

int vt_start(const char *vthost, const char *vtservice)
{
	struct addrinfo hints;

	INIT_LIST_HEAD(&vt_server_list);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	if (vt_server_init(vthost, vtservice, &hints) != 0) {
		VTDBG("VT init server failed\n");
		return -1;
	}
	if (pthread_create(&vt_listener, NULL, vt_server_recv, NULL))
		return -1;
	return 0;
}

int vt_bul_init(void)
{
	int ret;

	vt_cmd_init(&vt_cmd_bul);
	ret = vt_cmd_add_root(&vt_cmd_bul);
	if (ret < 0)
		return ret;

	vt_cmd_init(&vt_cmd_rr);
	ret = vt_cmd_add_root(&vt_cmd_rr);
	if (ret < 0)
		return ret;

	vt_cmd_init(&vt_cmd_ncn);
	ret = vt_cmd_add_root(&vt_cmd_ncn);
	if (ret < 0)
		return ret;

	return 0;
}

int vt_bc_init(void)
{
	int ret;

	vt_cmd_init(&vt_cmd_bc);
	ret = vt_cmd_add_root(&vt_cmd_bc);
	if (ret < 0)
		return ret;

	vt_cmd_init(&vt_cmd_nonce);
	ret = vt_cmd_add_root(&vt_cmd_nonce);
	if (ret < 0)
		return ret;

	return 0;
}

int vt_init(void)
{
	if (pthread_rwlock_init(&vt_lock, NULL))
		return -1;
	vt_cmd_init(&vt_cmd_root);
	return vt_cmd_sys_init();
}

void vt_fini(void)
{
	struct list_head *lp;

	list_for_each(lp,  &vt_server_list) {
		struct vt_server_entry *e;
		e = list_entry(lp, struct vt_server_entry, list);
		vt_server_close(e);
	}
	pthread_cancel(vt_listener);
	pthread_join(vt_listener, NULL);
	//vt_connect_fini(vt_connect_handle);
	vt_server_fini();
}
