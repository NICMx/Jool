# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "joold" is a "target".

bin_PROGRAMS = joold
joold_SOURCES = \
	hdr.c \
	joold.c \
	modsocket.c \
	netsocket.c \
	../common/cJSON.c \
	../common/file.c \
	../common/netlink2.c \
	../common/str_utils.c \
	../stateful/xlat.c

#	jool_client.c \
#	mcastutil.c \
#	receiver.c \
#	sender.c \
#	argp/options.c
	
joold_LDADD = ${LIBNLGENL3_LIBS} ${LIBNL3_LIBS}
joold_CFLAGS = -Wall -O2
joold_CFLAGS += -I${srcdir}/../../include
joold_CFLAGS += ${LIBNLGENL3_CFLAGS} ${LIBNL3_CFLAGS} ${JOOL_FLAGS}
#man_MANS = joold.8
