# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool_siit" is a "target".

bin_PROGRAMS = jool_siit
jool_siit_SOURCES = \
	../../common/common-global.c \
	../../common/netlink/config.c \
	../../common/siit/xlat.c \
	../common/cJSON.c \
	../common/command.c \
	../common/common-global.c \
	../common/dns.c \
	../common/file.c \
	../common/netlink.c \
	../common/requirements.c \
	../common/str_utils.c \
	../common/userspace-types.c \
	../common/wargp.c \
	\
	../common/argp/bib.c \
	../common/argp/blacklist4.c \
	../common/argp/eamt.c \
	../common/argp/file.c \
	../common/argp/global.c \
	../common/argp/instance.c \
	../common/argp/pool4.c \
	../common/argp/session.c \
	../common/argp/stats.c \
	\
	../common/nl/bib.c \
	../common/nl/blacklist4.c \
	../common/nl/buffer.c \
	../common/nl/eamt.c \
	../common/nl/global.c \
	../common/nl/instance.c \
	../common/nl/joold.c \
	../common/nl/json.c \
	../common/nl/pool4.c \
	../common/nl/session.c \
	../common/nl/stats.c \
	\
	../common/jool.c

jool_siit_LDADD = ${LIBNLGENL3_LIBS}
jool_siit_CFLAGS = -Wall -O2
jool_siit_CFLAGS += -I${srcdir}/../../
jool_siit_CFLAGS += ${LIBNLGENL3_CFLAGS} ${JOOL_FLAGS}
man_MANS = jool_siit.8
