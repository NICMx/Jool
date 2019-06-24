# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "joold" is a "target".

bin_PROGRAMS = joold
joold_SOURCES = \
	joold.c \
	log.c log.h \
	modsocket.c modsocket.h \
	netsocket.c netsocket.h

joold_CFLAGS  = -Wall -O2
joold_CFLAGS += -I${srcdir}/../../
joold_CFLAGS += ${LIBNLGENL3_CFLAGS}
joold_CFLAGS += ${JOOL_FLAGS}
joold_CFLAGS += -DJOOLD

joold_LDADD  = ${LIBNLGENL3_LIBS}
joold_LDADD += ${top_builddir}/src/usr/nl/libjoolnl.la
joold_LDADD += ${top_builddir}/src/usr/util/libjoolutil.la

dist_man_MANS = joold.8
