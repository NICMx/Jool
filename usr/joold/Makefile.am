# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "joold" is a "target".

bin_PROGRAMS = joold
joold_SOURCES = joold.c \
	jool_client.c \
	mcastutil.c \
	receiver.c \
	sender.c \
	argp/options.c \
	../stateful/xlat.c \
	../common/netlink2.c
	
joold_LDADD = ${LIBNLGENL3_LIBS} ${LIBNL3_LIBS}
joold_CFLAGS = -Wall -O2
joold_CFLAGS += -I${srcdir}/../../include
joold_CFLAGS += ${LIBNLGENL3_CFLAGS} ${LIBNL3_CFLAGS} ${JOOL_FLAGS}
#man_MANS = joold.8
