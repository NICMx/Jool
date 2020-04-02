#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([Graybox], [1.0.0], [jool@nic.mx])
AC_CONFIG_SRCDIR([graybox.c])
AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CC

# Dumb autoconf noise, needed until automake 1.14
AM_PROG_CC_C_O

# Checks for dependencies.
PKG_CHECK_MODULES(LIBNLGENL3, libnl-genl-3.0 >= 3.1)

# Spit out the makefile.
AC_OUTPUT(Makefile)
