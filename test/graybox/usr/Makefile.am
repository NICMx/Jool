# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "graybox" is a "target".

bin_PROGRAMS = graybox
graybox_SOURCES = \
	graybox.c \
	genetlink.c genetlink.h \
	command/expect.c command/expect.h \
	command/send.c command/send.h \
	command/stats.c command/stats.h \
	command/common.c command/common.h

graybox_CFLAGS  = ${WARNINGCFLAGS}
graybox_CFLAGS += -I${srcdir}/..
graybox_CFLAGS += -I${srcdir}/../../../src
graybox_CFLAGS += ${LIBNLGENL3_CFLAGS}

graybox_LDADD  = ${LIBNLGENL3_LIBS}
graybox_LDADD += ${top_builddir}/src/usr/util/libjoolutil.la
graybox_LDADD += ${top_builddir}/src/usr/argp/libjoolargp.la

man_MANS = graybox.7
