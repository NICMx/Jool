CC = gcc
LD = ld

INCDIRS += -Iinclude -I../../include 
INCDIRS += $(shell pkg-config --cflags libnl-3.0)
CFLAGS += -Wall ${INCDIRS}

KERNEL_VER = $(shell uname -r | cut -d'-' -f1| cut -f1 -d.)
# For netlink sockets include library: libnl
ifeq "${KERNEL_VER}" "2"
#	For Ubuntu 10.04
LDLIBS += -lnl-3
$(info Compiling on kernel family 2)
else
# 	For Ubuntu 12.04
LDLIBS += $(shell pkg-config --libs libnl-3.0)
$(info Compiling on kernel family 3)
endif

# Programs to compile:
progs = nat64 
#progs = load_config static_route 

default: all

all: $(progs)

#load_config:load_config.o include/confuse.o include/lexer.o nat64_config_validation.o
#load_config.o: load_config.c
#include/confuse.o:include/confuse.c
#include/lexer.o:include/lexer.c

nat64: nat64_config_validation.o ../../mod/nf_nat64_types.o nat64.o  
nat64_config_validation.o: nat64_config_validation.c
../../mod/nf_nat64_types.o: ../../mod/nf_nat64_types.c
nat64.o: nat64.c

#static_route: static_route.o
#static_route.o: static_route.c

#%.o: %.c

clean:
	rm -f *.o
	rm -f include/*.o
	rm -f $(progs)
