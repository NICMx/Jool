# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool_siit" is a "target".

bin_PROGRAMS = jool_siit
jool_siit_SOURCES = \
	../../common/netlink/config.c \
	../../common/stateless/xlat.c \
	../common/cJSON.c \
	../common/dns.c \
	../common/file.c \
	../common/jool.c \
	../common/netlink2.c \
	../common/str_utils.c \
	../common/argp/options.c \
	../common/nl/buffer.c \
	../common/target/bib.c \
	../common/target/eam.c \
	../common/target/global.c \
	../common/target/instance.c \
	../common/target/joold.c \
	../common/target/json.c \
	../common/target/log_time.c \
	../common/target/pool.c \
	../common/target/pool4.c \
	../common/target/pool6.c \
	../common/target/session.c

jool_siit_LDADD = ${LIBNLGENL3_LIBS}
jool_siit_CFLAGS = -Wall -O2
jool_siit_CFLAGS += -I${srcdir}/../../include
jool_siit_CFLAGS += ${LIBNLGENL3_CFLAGS} ${JOOL_FLAGS}
man_MANS = jool_siit.8
