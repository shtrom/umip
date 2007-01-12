/* $Id: proc_sys.h 1.3 05/12/26 01:19:12+09:00 aramoto@springbank.sharp.net $ */

#ifndef __PROC_SYS_H__
#define __PROC_SYS_H__ 1

const char *conf_path;
const char *neigh_path;

const char *autoconf_file;
const char *ra_defrtr_file;
const char *ra_pinfo_file;
const char *rs_file;
const char *rs_ival_file;
const char *app_ns_file;

const char *hoplimit_file;
const char *mtu_file;
const char *retransmit_file;

int set_iface_proc_entry(const char *path, const char *if_name,
			 const char *file, int val);

int get_iface_proc_entry(const char *path, const char *if_name,
			 const char *file, int *val);

#endif
