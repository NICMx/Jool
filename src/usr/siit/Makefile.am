# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool_siit" is a "target".

bin_PROGRAMS = jool_siit
jool_siit_SOURCES = wrapper-xlat.c

jool_siit_CFLAGS  = -Wall -O2
jool_siit_CFLAGS += -I${srcdir}/../../
jool_siit_CFLAGS += ${JOOL_FLAGS}

jool_siit_LDADD = ${top_builddir}/src/usr/argp/libjoolargp.la

dist_man_MANS = jool_siit.8

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
dist_bashcompletion_DATA = jool_siit.bash
endif
