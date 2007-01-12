## $Id: Makefile.am 1.47 05/12/08 19:42:43+02:00 vnuorval@tcs.hut.fi $
## Process this file with automake to produce Makefile.in

AM_CFLAGS = -Wall -std=gnu99
AM_CPPFLAGS = -I../include
AM_YFLAGS = -d

edit = sed \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
        -e 's,@sbindir\@,$(sbindir),g'

defpath.h: Makefile defpath.h.in
	$(edit) defpath.h.in > defpath.h.tmp
	mv -f defpath.h.tmp defpath.h

pmgr.c: mk-pmgr_c.sh pmgr.c.in policy.h
	sh mk-pmgr_c.sh

pmgr.h: mk-pmgr_h.sh pmgr.h.in policy.h
	sh mk-pmgr_h.sh

BUILT_SOURCES = defpath.h pmgr.c pmgr.h
EXTRA_DIST = mk-pmgr_c.sh mk-pmgr_h.sh pmgr.c.in pmgr.h.in defpath.h.in

sbin_PROGRAMS = mip6d

mip6d_SOURCES = pmgr.c pmgr.h defpath.h \
		main.c vars.c mipv6.h \
		conf.c conf.h \
		gram.y scan.l \
		tqueue.c tqueue.h \
		icmp6.c icmp6.h \
		list.h util.h \
		hash.c hash.h \
		debug.c debug.h \
		dhaad_ha.c dhaad_ha.h \
		dhaad_mn.c dhaad_mn.h \
		ndisc.c ndisc.h \
		mh.c mh.h \
		mn.c mn.h \
		bul.c bul.h \
		bcache.c bcache.h \
		retrout.c retrout.h \
		mpdisc_ha.c mpdisc_ha.h \
		mpdisc_mn.c mpdisc_mn.h \
		tunnelctl.c tunnelctl.h \
		rtnl.c rtnl.h \
		ha.c ha.h \
		cn.c cn.h \
		keygen.c keygen.h \
		movement.c movement.h \
		policy.c policy.h \
		xfrm.c xfrm.h \
		proc_sys.c proc_sys.h \
		prefix.c prefix.h \
		ipsec.c ipsec.h \
		rfc3542.h

if ENABLE_VT
mip6d_SOURCES += vt.c vt.h
endif

mip6d_LDADD = -L../libnetlink -lnetlink -L../libmissing -lmissing

noinst_HEADERS = ../include/netinet-icmp6.h \
		 ../include/netinet-in.h \
		 ../include/netinet-ip6.h \
		 ../include/netinet-ip6mh.h
