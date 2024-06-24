bin_PROGRAMS = jnetflow
jnetflow_SOURCES = jnetflow.c

jnetflow_CFLAGS  = ${WARNINGCFLAGS}
jnetflow_CFLAGS += -I${top_srcdir}/src
jnetflow_CFLAGS += ${LIBNLGENL3_CFLAGS}

jnetflow_LDADD  = ${LIBNLGENL3_LIBS}
jnetflow_LDADD += ../nl/libjoolnl.la
jnetflow_LDADD += ../util/libjoolutil.la
