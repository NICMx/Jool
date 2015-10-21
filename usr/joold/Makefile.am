# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".

bin_PROGRAMS = joold
joold_SOURCES = \
	jool_client.c \
	joold.c \
	mcastutil.c \
	receiver.c \
	sender.c \
	argp/options.c
	
joold_LDADD = ${LIBNL3_LIBS}
joold_CFLAGS = -Wall -O2
joold_CFLAGS += -I${srcdir}/../../include
joold_CFLAGS += ${LIBNL3_CFLAGS} ${JOOL_FLAGS}
#man_MANS = jool.8
