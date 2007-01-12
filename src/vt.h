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
#ifndef __VT_H
#define __VT_H 1

#include "list.h"

#define VT_DEFAULT_HOSTNAME	"localhost"
#define VT_DEFAULT_SERVICE	"7777" /* string */

typedef enum {
	VT_BOOL_TRUE = 0,
	VT_BOOL_FALSE,
} vt_bool_t;

struct vt_opt {
	vt_bool_t prompt;
	vt_bool_t verbose;
	vt_bool_t fancy;
};

struct vt_info {
	struct vt_opt opt;
};

struct vt_handle {
	struct vt_opt vh_opt;
	int vh_sock;
};

struct vt_cmd_entry {
	char *cmd;
	char *cmd_alias;
	int (*parser)(const struct vt_handle *vh, const char *str);
	struct list_head list;
	struct vt_cmd_entry *parent;
	struct list_head child_list;
};

ssize_t vt_printf(const struct vt_handle *vh, const char *fmt, ...);
ssize_t vt_printf_b(const struct vt_handle *vh, const char *fmt, ...);
ssize_t vt_printf_bl(const struct vt_handle *vh, const char *fmt, ...);
const struct vt_info *vt_info_get(void);
int vt_cmd_add(struct vt_cmd_entry *parent, struct vt_cmd_entry *e);
int vt_cmd_add_root(struct vt_cmd_entry *e);
int vt_cmd_init(struct vt_cmd_entry *e);
int vt_start(const char *vthost, const char *vtservice);

int vt_bul_init(void);

int vt_bc_init(void);

int vt_init(void);
void vt_fini(void);

#endif
