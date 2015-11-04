# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".

bin_PROGRAMS = jool
jool_SOURCES = \
	../common/dns.c \
	../common/jool.c \
	../common/netlink.c \
	../common/str_utils.c \
	../common/argp/options.c \
	../common/target/bib.c \
	../common/target/eam.c \
	../common/target/global.c \
	../common/target/log_time.c \
	../common/target/pool.c \
	../common/target/pool4.c \
	../common/target/pool6.c \
	../common/target/session.c \
	xlat.c

jool_LDADD = ${LIBNL3_LIBS}
jool_CFLAGS = -Wall -O2
jool_CFLAGS += -I${srcdir}/../../include
jool_CFLAGS += ${LIBNL3_CFLAGS} ${JOOL_FLAGS}
man_MANS = jool.8
