# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "joold" is a "target".

bin_PROGRAMS = joold
joold_SOURCES = \
	joold.c \
	json.c json.h \
	log.h

joold_CFLAGS  = ${WARNINGCFLAGS}
joold_CFLAGS += -I${top_srcdir}/src
joold_CFLAGS += ${LIBNLGENL3_CFLAGS}

joold_LDADD  = ${LIBNLGENL3_LIBS}
joold_LDADD += ../nl/libjoolnl.la
joold_LDADD += ../util/libjoolutil.la
joold_LDADD += ../argp/libjoolargp.la

dist_man_MANS = joold.8
