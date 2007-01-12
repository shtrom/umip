/*
 * $Id: proc_sys.c 1.6 05/12/26 01:19:12+09:00 aramoto@springbank.sharp.net $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 * 
 * Author: Ville Nuorvala <vnuorval@tcs.hut.fi>
 *
 * Copyright 2003-2004 GO-Core Project
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

#include <string.h>
#include <stdio.h>

#include <net/if.h>

#define PROC_SYS_BUF_SIZE 32

const char *conf_path = "/proc/sys/net/ipv6/conf/";
const char *neigh_path = "/proc/sys/net/ipv6/neigh/";

const char *autoconf_file = "/autoconf";
const char *ra_defrtr_file = "/accept_ra_defrtr";
const char *ra_pinfo_file = "/accept_ra_pinfo";
const char *rs_file = "/router_solicitations";
const char *rs_ival_file = "/router_solicitation_interval";
const char *app_ns_file = "/app_solicit";

const char *hoplimit_file = "/hop_limit";
const char *retransmit_file = "/retrans_time_ms";

static int proc_sys_get_string(const char *filename, char *buf, int buflen)
{
	FILE *fp;
	int res = -1;

	if ((fp = fopen(filename, "r"))) {
		if ((buf = fgets(buf, buflen, fp)))
			res = 0;
		fclose(fp);
	}
	return res;
} 

static int proc_sys_set_string(const char *filename, char *buf, int buflen)
{
	FILE *fp;
	int res = -1;

	if ((fp = fopen(filename, "w"))) {
		buf[buflen - 1] = 0;
		if (fputs(buf, fp) > 0)
			res = 0;
		fclose(fp);
	}
	return res;
} 

static int proc_sys_get_int(const char *filename, int *ival)
{
	char buf[PROC_SYS_BUF_SIZE];
	if (!proc_sys_get_string(filename, buf, PROC_SYS_BUF_SIZE))
		if (sscanf(buf,"%d", ival) >  0)
			return 0;
	return -1;
} 

static int proc_sys_set_int(const char *filename, int ival)
{
	char buf[PROC_SYS_BUF_SIZE];
	if (sprintf(buf,"%d", ival) >  0) {
		return proc_sys_set_string(filename, buf, PROC_SYS_BUF_SIZE);
	}
	return -1;
}

int set_iface_proc_entry(const char *path, const char *if_name,
			 const char *file, int val)
{
	char buf[256];
	memset(buf, 0, sizeof(buf));
	strcpy(buf, path);
	strncat(buf, if_name, IF_NAMESIZE-1);
	strcat(buf, file);
	return proc_sys_set_int(buf, val);
}

int get_iface_proc_entry(const char *path, const char *if_name,
			    const char *file, int *val)
{
	char buf[256];
	memset(buf, 0, sizeof(buf));
	strcpy(buf, path);
	strncat(buf, if_name, IF_NAMESIZE-1);
	strcat(buf, file);
	return proc_sys_get_int(buf, val);

}

