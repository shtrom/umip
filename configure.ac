dnl $Id: configure.ac 1.28 05/11/24 21:28:53+09:00 shinta@area51.linux-ipv6.org $
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([MIPL Mobile IPv6 for Linux], [2.0-rc3], 
	[URL:http://www.mobile-ipv6.org/bugs/], mipv6)
AC_DEFINE_UNQUOTED([PACKAGE_COPYRIGHT],
	["Copyright (C) 2003-2005 GO-Core Project, and others"], 
	[Define to the copyright statement])

AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_REVISION($Revision: 1.28 $)
AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_CHECK_PROG(SED, sed, sed)

# Option --disable-debug
AC_MSG_CHECKING(if --disable-debug option is specified)
AC_ARG_ENABLE(debug,
        [  --disable-debug         disable debugging messages and asserts],
        [disable_debug=yes], [disable_debug=no])
if test $disable_debug = "yes"; then
        AC_DEFINE([MIP6_NDEBUG], [1], [Disable debugging])
fi
AC_MSG_RESULT($disable_debug)

# Option --enable-vt
AC_MSG_CHECKING(if --enable-vt option is specified)
AC_ARG_ENABLE(vt,
        [  --enable-vt             enable virtual terminal for debugging],
        [enable_vt=yes], [enable_vt=no])
if test $enable_vt = "yes"; then
        AC_DEFINE([ENABLE_VT], [1], [Enable VT])
fi
AC_MSG_RESULT($enable_vt)
AM_CONDITIONAL(ENABLE_VT, test x$enable_vt = xyes)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL

AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETPGRP
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gethostbyaddr memset socket strcasecmp strchr strdup strtol strtoul])

AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB(crypto, HMAC_Init)
AC_REPLACE_FUNCS(inet6_opt_find)
AC_REPLACE_FUNCS(inet6_rth_space)
AC_REPLACE_FUNCS(inet6_rth_init)
AC_REPLACE_FUNCS(inet6_rth_add)
AC_REPLACE_FUNCS(inet6_rth_getaddr)
AC_REPLACE_FUNCS(inet6_rth_gettype)

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h time.h syslog.h unistd.h])

AC_CHECK_HEADERS([netinet/ip6mh.h])
AC_CHECK_MEMBER(struct ip6_opt_home_address.ip6oha_type,
		AC_DEFINE([HAVE_MIP6_IP6_H],,[Define to 1 if MIPv6 extensions in <netinet/ip6.h> header file.]),,
		[#include <netinet/ip6.h>])
AC_CHECK_MEMBER(struct mip_dhaad_req.mip_dhreq_hdr,
		AC_DEFINE([HAVE_MIP6_ICMP6_H],,[Define to 1 if MIPv6 extensions in <netinet/icmp6.h> header file.]),,
		[#include <netinet/icmp6.h>])

AC_CONFIG_FILES([Makefile libnetlink/Makefile libmissing/Makefile src/Makefile man/Makefile])
AC_OUTPUT
