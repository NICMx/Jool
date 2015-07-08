# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool_siit" is a "target".
# If you want to activate the benchmark feature, you need to uncomment
# log_time.c and -DBENCHMARK below.

bin_PROGRAMS = jool_siit
jool_siit_SOURCES = \
	../common/dns.c \
	../common/jool.c \
	../common/netlink.c \
	../common/str_utils.c \
	../common/argp/options.c \
	../common/target/pool6.c \
	../common/target/pool4.c \
	../common/target/eam.c \
	../common/target/pool.c \
	../common/target/bib.c \
	../common/target/session.c \
	../common/target/global.c \
	xlat.c
#jool_siit_SOURCES += ../common/log_time.c

jool_siit_LDADD = ${LIBNL3_LIBS}
jool_siit_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS}
#jool_siit_CFLAGS += -DBENCHMARK
man_MANS = jool_siit.8
