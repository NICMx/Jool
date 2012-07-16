CC = gcc
CCFLAGS = -Wall 
LD = ld 
# para netlink library : libnl
LDFLAGS += -lnl

progs = load_config 

# gcc -Wall  load_config.c include/confuse.c include/lexer.c -I./include/ -o load_config

#all:load_config

#load_config:load_config.c, include/confuse.c, include/lexer.c 
#	$(CC) $(CCFLAGS) load_config.c include/confuse.c include/lexer.c -o load_config

#~ all: load_config
all: $(progs)

load_config:load_config.o include/confuse.o include/lexer.o
#	$(CC) $(CCFLAGS) load_config.c include/confuse.c include/lexer.c -o load_config
load_config.o: load_config.c
include/confuse.o:include/confuse.c
include/lexer.o:include/lexer.c

#%.o: %.c

clean:
	rm -f *.o
	rm -f $(progs)
	#~ rm -f load_config
