# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".
# If you want to activate the benchmark feature, you need to uncomment
# log_time.c and -DBENCHMARK below.

bin_PROGRAMS = jool
jool_SOURCES = \
	../common/dns.c \
	../common/jool.c \
	../common/netlink.c \
	../common/str_utils.c \
	../common/cJSON.c \
	../common/argp/options.c \
	../common/target/pool6.c \
	../common/target/pool4.c \
	../common/target/eam.c \
	../common/target/pool.c \
	../common/target/bib.c \
	../common/target/session.c \
	../common/target/global.c \
	xlat.c \
	JsonReader.c
#jool_SOURCES += ../common/log_time.c

jool_LDADD = ${LIBNL3_LIBS}
jool_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS}
#jool_CFLAGS += -DBENCHMARK
man_MANS = jool.8
