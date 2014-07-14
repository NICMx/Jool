AM_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS}

# Note to myself: documentation tends to call these "PROGRAMS" "targets". "jool" is a "target".

bin_PROGRAMS = jool
jool_SOURCES = bib.c fragmentation.c pool4.c session.c translate.c \
		filtering.c jool.c netlink.c pool6.c str_utils.c dns.c
jool_LDADD = ${LIBNL3_LIBS}
