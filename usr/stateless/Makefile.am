# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool_siit" is a "target".

bin_PROGRAMS = jool_siit
jool_siit_SOURCES = \
	../common/dns.c \
	../common/jool2.c \
	../common/netlink2.c \
	../common/str_utils.c \
	../common/cJSON.c \
	../common/JsonReaderCommon.c \
	../common/argp/options.c \
	../common/target/bib.c \
	../common/target/eam.c \
	../common/target/global.c \
	../common/target/log_time.c \
	../common/target/pool.c \
	../common/target/pool4.c \
	../common/target/pool6.c \
	../common/target/session.c \
	xlat.c \
	JsonReader.c

jool_siit_LDADD = ${LIBNLGENL3_LIBS} -lm
jool_siit_CFLAGS = -Wall -O2
jool_siit_CFLAGS += -I${srcdir}/../../include
jool_siit_CFLAGS += ${LIBNLGENL3_CFLAGS} ${LIBNL3_CFLAGS} ${JOOL_FLAGS}
man_MANS = jool_siit.8
