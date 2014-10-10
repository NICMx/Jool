AM_CFLAGS = -Wall -O2 -I${srcdir}/../../include ${LIBNL3_CFLAGS}

# Note to myself: documentation tends to call these "PROGRAMS" "targets". "jool" is a "target".

bin_PROGRAMS = jool
jool_SOURCES = pool4.c pool6.c bib.c session.c general.c \
		 dns.c netlink.c str_utils.c jool.c

# Note: if you want to activate the benchmark feature, you need to activate the following flags, 
#	also you need to activate in the mod-app (Kbuild)
#AM_CFLAGS += -DBENCHMARK
#jool_SOURCES += log_time.c
		 
jool_LDADD = ${LIBNL3_LIBS}
