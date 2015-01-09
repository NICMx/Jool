AM_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS}

# Note to myself: documentation tends to call these "PROGRAMS" "targets". "jool" is a "target".

bin_PROGRAMS = jool
# TODO: is this correct?
# Note: uncomment this if you want the stateful user app, and comment the second jool_SOURCES.
#AM_CFLAGS += -DSTATEFUL
#jool_SOURCES = pool4.c pool6.c bib.c session.c global.c \
		 dns.c netlink.c str_utils.c jool.c

# Note: uncomment this if you want the stateles user app, and comment the first jool_SOURCES.
jool_SOURCES = global.c dns.c netlink.c str_utils.c eam.c jool.c

# Note: if you want to activate the benchmark feature, you need to activate the following flags, 
#	also you need to activate in the mod-app (Kbuild)
#AM_CFLAGS += -DBENCHMARK
#jool_SOURCES += log_time.c
		 
jool_LDADD = ${LIBNL3_LIBS}
