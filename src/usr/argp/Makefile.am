pkglib_LTLIBRARIES = libjoolargp.la

libjoolargp_la_SOURCES = \
	client.c \
	command.c command.h \
	dns.c dns.h \
	log.c log.h \
	requirements.c requirements.h \
	userspace-types.c userspace-types.h \
	wargp.c wargp.h \
	\
	wargp/bib.c wargp/bib.h \
	wargp/blacklist4.c wargp/blacklist4.h \
	wargp/eamt.c wargp/eamt.h \
	wargp/file.c wargp/file.h \
	wargp/global.c wargp/global.h \
	wargp/instance.c wargp/instance.h \
	wargp/pool4.c wargp/pool4.h \
	wargp/session.c wargp/session.h \
	wargp/stats.c wargp/stats.h

libjoolargp_la_CFLAGS  = ${WARNINGCFLAGS}
libjoolargp_la_CFLAGS += -I${srcdir}/../../
libjoolargp_la_CFLAGS += ${LIBNLGENL3_CFLAGS}

libjoolargp_la_LIBADD = ${top_builddir}/src/usr/nl/libjoolnl.la
