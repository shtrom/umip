## $Id: Makefile.am 1.12 06/05/07 17:37:11+03:00 anttit@tcs.hut.fi $
## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnu
EXTRA_DIST = BUGS INSTALL.kernel README.IPsec chkconf_kernel.sh \
	     README.IPsec  README.NEMO  README.v4traffic \
	     extras/example-cn.conf extras/example-ha.conf \
	     extras/example-mn.conf \
	     extras/example-nemo-ha.conf extras/example-nemo-mn.conf \
	     extras/example-dsmip-ha.conf extras/example-dsmip-mn.conf \
	     extras/example-nemo-dsmip-v4traffic-ha.conf extras/example-nemo-dsmip-v4traffic-mr.conf  


if MISSING
LIBMISSING = libmissing
endif
SUBDIRS = $(LIBMISSING) libnetlink src man
