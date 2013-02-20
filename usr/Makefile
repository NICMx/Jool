CC = gcc
LD = ld

INCDIRS += -Iinclude -I../include
INCDIRS += $(shell pkg-config --cflags libnl-3.0)
CFLAGS += -Wall ${INCDIRS}

KERNEL_VER = $(shell uname -r | cut -d'-' -f1 | cut -f1 -d.)
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

PROGS = nat64
OBJS := str_utils.o netlink.o pool6.o pool4.o bib.o session.o filtering.o translate.o nat64.o


nat64: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDLIBS)

str_utils.o: str_utils.c
	$(CC) -c $(CFLAGS) $< -o $@

netlink.o: netlink.c
	$(CC) -c $(CFLAGS) $< -o $@
pool6.o: pool6.c
	$(CC) -c $(CFLAGS) $< -o $@
pool4.o: pool4.c
	$(CC) -c $(CFLAGS) $< -o $@
bib.o: bib.c
	$(CC) -c $(CFLAGS) $< -o $@
session.o: session.c
	$(CC) -c $(CFLAGS) $< -o $@
filtering.o: filtering.c
	$(CC) -c $(CFLAGS) $< -o $@
translate.o: translate.c
	$(CC) -c $(CFLAGS) $< -o $@

nat64.o: nat64.c
	$(CC) -c $(CFLAGS) $< -o $@

all: nat64

clean:
	rm -f $(PROGS) $(OBJS)
