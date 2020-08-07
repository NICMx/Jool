# Note to myself: documentation tends to call these "PROGRAMS" "targets".
# "jool_mapt" is a "target".

bin_PROGRAMS = jool_mapt
jool_SOURCES = main-mapt.c

jool_CFLAGS  = ${WARNINGCFLAGS}
jool_CFLAGS += -I${top_srcdir}/src

jool_LDADD = ../argp/libjoolargp.la

#dist_man_MANS = jool_mapt.8

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
dist_bashcompletion_DATA = jool_mapt.bash
endif
