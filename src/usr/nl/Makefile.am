pkglib_LTLIBRARIES = libjoolnl.la

libjoolnl_la_SOURCES = \
	address.c address.h \
	bib.c bib.h \
	blacklist4.c blacklist4.h \
	buffer.c buffer.h \
	eamt.c eamt.h \
	global.c global.h \
	global-impl.c \
	instance.c instance.h \
	jool_socket.c jool_socket.h \
	joold.c joold.h \
	json.c json.h \
	pool4.c pool4.h \
	session.c session.h \
	stats.c stats.h \
	wrapper-config.c \
	wrapper-globals.c \
	wrapper-types.c

libjoolnl_la_CFLAGS  = ${WARNINGCFLAGS}
libjoolnl_la_CFLAGS += -I${srcdir}/../../
libjoolnl_la_CFLAGS += ${LIBNLGENL3_CFLAGS}

libjoolnl_la_LIBADD  = ${LIBNLGENL3_LIBS}
libjoolnl_la_LIBADD += ${top_builddir}/src/usr/util/libjoolutil.la

