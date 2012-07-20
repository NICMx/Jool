CC = gcc
INCDIRS = -Iinclude -I../../include
CFLAGS += -Wall ${INCDIRS} 
LD = ld 
# For netlink sockets include library: libnl
LDFLAGS += -lnl

# Programs to compile:
progs = load_config 


# To read one or more other makefiles before continuing
#include filenames...
# a typical `descend into a directory' recipe then looks like this:
#${subdirs}:
#	${MAKE} -C $@ all


default: all

all: $(progs)

load_config:load_config.o include/confuse.o include/lexer.o
#	$(CC) $(CCFLAGS) load_config.c include/confuse.c include/lexer.c -o load_config
load_config.o: load_config.c
include/confuse.o:include/confuse.c
include/lexer.o:include/lexer.c

#%.o: %.c

clean:
	rm -f *.o
	rm -f include/*.o
	rm -f $(progs)
