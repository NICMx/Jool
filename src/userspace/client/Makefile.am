# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".

bin_PROGRAMS = jool
jool_SOURCES = \
	dns.c \
	jool.c \
	nl-buffer.c \
	options.c \
	../common/cJSON.c \
	../common/file.c \
	../common/netlink.c \
	../common/usr-str-utils.c \
	target/bib.c \
	target/eam.c \
	target/global.c \
	target/instance.c \
	target/joold.c \
	target/json.c \
	target/pool4.c \
	target/session.c

jool_LDADD = ${LIBNLGENL3_LIBS}
jool_CFLAGS = -Wall -O2
jool_CFLAGS += -I${srcdir}/../common
jool_CFLAGS += -I${srcdir}/../../common
jool_CFLAGS += ${LIBNLGENL3_CFLAGS} ${JOOL_FLAGS}
man_MANS = jool.8
