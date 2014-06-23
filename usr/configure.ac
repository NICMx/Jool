#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Jool], [3.1.5], [jool@nic.mx])
AC_CONFIG_SRCDIR([src/jool.c])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([nl-3], [nl_send_simple], [],[
	echo "Could not find the Netlink library. Please install libnl-3-dev."
	exit -1])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([inet_ntoa memset strcasecmp strtol])

AC_OUTPUT(Makefile src/Makefile man/Makefile)

