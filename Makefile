CC = gcc
LD = ld 

# First approach:
# To read one or more other makefiles before continuing
#include filenames...

# Second approach:
# a typical `descend into a directory' recipe then looks like this:
#${subdirs}:
#	${MAKE} -C $@ all
subdirs = etc/nat64_configuration mod
#subdirs = mod
${subdirs}:
	${MAKE} -C $@ all

default: all

all: ${subdirs}

