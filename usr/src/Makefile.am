AM_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS}

# Note to myself: documentation tends to call these "PROGRAMS" "targets". "jool" is a "target".

bin_PROGRAMS = jool
jool_SOURCES = pool4.c pool6.c bib.c session.c general.c \
		 dns.c netlink.c str_utils.c jool.c
jool_LDADD = ${LIBNL3_LIBS}
