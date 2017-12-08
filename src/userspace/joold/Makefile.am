# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "joold" is a "target".

bin_PROGRAMS = joold
joold_SOURCES = \
	joold.c \
	modsocket.c \
	netsocket.c \
	../../common/netlink/config.c \
	../../common/stateful/xlat.c \
	../common/cJSON.c \
	../common/file.c \
	../common/log.c \
	../common/netlink2.c \
	../common/str_utils.c

joold_LDADD = ${LIBNLGENL3_LIBS}
joold_CFLAGS = -Wall -O2
joold_CFLAGS += -I${srcdir}/../../include
joold_CFLAGS += ${LIBNLGENL3_CFLAGS} ${JOOL_FLAGS} -DJOOLD
#man_MANS = joold.8
