# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool_stateful" is a "target".
# If you want to activate the benchmark feature, you need to uncomment
# log_time.c and -DBENCHMARK below.

bin_PROGRAMS = jool_stateful
jool_stateful_SOURCES = \
	../common/dns.c \
	../common/global.c \
	../common/jool.c \
	../common/netlink.c \
	../common/pool4.c \
	../common/str_utils.c \
	../common/pool6.c \
	bib.c \
	session.c
#jool_stateful_SOURCES += ../common/log_time.c

jool_stateful_LDADD = ${LIBNL3_LIBS}
jool_stateful_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS} -DSTATEFUL
#jool_stateful_CFLAGS += -DBENCHMARK
jool_stateful_MANS = jool_stateful.8
