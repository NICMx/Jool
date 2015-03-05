# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".
# If you want to activate the benchmark feature, you need to uncomment
# log_time.c and -DBENCHMARK below.

bin_PROGRAMS = jool
jool_SOURCES = \
	../common/dns.c \
	../common/global.c \
	../common/jool.c \
	../common/netlink.c \
	../common/pool4.c \
	../common/str_utils.c \
	../common/pool6.c \
	bib.c \
	session.c
#jool_SOURCES += ../common/log_time.c

jool_LDADD = ${LIBNL3_LIBS}
jool_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS} -DSTATEFUL
#jool_CFLAGS += -DBENCHMARK
man_MANS = jool.8

