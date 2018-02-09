# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".

bin_PROGRAMS = jool
# nl-buffer.c
jool_SOURCES = \
	../../common/common-global.c \
	dns.c \
	jool.c \
	requirements.c \
	wargp.c \
	../common/cJSON.c \
	../common/netlink.c \
	../common/usr-str-utils.c \
	argp/bib.c \
	argp/eamt.c \
	argp/global.c \
	argp/instance.c \
	argp/pool4.c \
	argp/session.c \
	netlink/bib.c \
	netlink/eamt.c \
	netlink/global.c \
	netlink/instance.c \
	netlink/pool4.c \
	netlink/session.c

jool_LDADD = ${LIBNLGENL3_LIBS}
jool_CFLAGS = -Wall -O2
jool_CFLAGS += -I${srcdir}/../common
jool_CFLAGS += -I${srcdir}/../../common
jool_CFLAGS += ${LIBNLGENL3_CFLAGS} ${JOOL_FLAGS}
man_MANS = jool.8
