# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool" is a "target".

bin_PROGRAMS = jool
jool_SOURCES = wrapper-xlat.c

jool_CFLAGS  = ${WARNINGCFLAGS}
jool_CFLAGS += -I${srcdir}/../../

jool_LDADD = ${top_builddir}/src/usr/argp/libjoolargp.la

dist_man_MANS = jool.8

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
dist_bashcompletion_DATA = jool.bash
endif
