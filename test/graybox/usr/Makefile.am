# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "graybox" is a "target".

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = graybox
graybox_SOURCES = \
	graybox.c \
	genetlink.c \
	command/expect.c \
	command/send.c \
	command/stats.c \
	command/common.c \
	../../../src/usr/common/str_utils.c

graybox_LDADD = ${LIBNLGENL3_LIBS}
graybox_CFLAGS = -Wall -O2
graybox_CFLAGS += -I${srcdir}/../common
graybox_CFLAGS += -I${srcdir}/../../../src
graybox_CFLAGS += ${LIBNLGENL3_CFLAGS}
man_MANS = graybox.7
