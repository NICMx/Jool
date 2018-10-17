# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".

bin_PROGRAMS = jool
jool_SOURCES = \
	../../common/netlink/config.c \
	../../common/nat64/xlat.c \
	../common/cJSON.c \
	../common/dns.c \
	../common/file.c \
	../common/jool.c \
	../common/netlink2.c \
	../common/str_utils.c \
	../common/argp/options.c \
	../common/nl/buffer.c \
	../common/nl/bib.c \
	../common/nl/eam.c \
	../common/nl/global.c \
	../common/nl/instance.c \
	../common/nl/joold.c \
	../common/nl/json.c \
	../common/nl/pool.c \
	../common/nl/pool4.c \
	../common/nl/session.c

jool_LDADD = ${LIBNLGENL3_LIBS}
jool_CFLAGS = -Wall -O2
jool_CFLAGS += -I${srcdir}/../../
jool_CFLAGS += ${LIBNLGENL3_CFLAGS} ${JOOL_FLAGS}
man_MANS = jool.8
