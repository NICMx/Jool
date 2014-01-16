CC = cgcc
LD = ld

INCDIRS += -Iinclude -I../include
INCDIRS += $(shell pkg-config --cflags libnl-3.0)
# TODO this is too specific for our setup. Remove it for the release.
INCDIRS += -I/usr/include/x86_64-linux-gnu

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

PROGS = jool
OBJS := str_utils.o 
OBJS += netlink.o 
OBJS += pool6.o 
OBJS += pool4.o 
OBJS += bib.o 
OBJS += session.o 
OBJS += filtering.o 
OBJS += translate.o 
OBJS += jool.o 
OBJS += fragmentation.o


jool: $(OBJS)
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
fragmentation.o: fragmentation.c
	$(CC) -c $(CFLAGS) $< -o $@

jool.o: jool.c
	$(CC) -c $(CFLAGS) $< -o $@

all: jool

clean:
	rm -f $(PROGS) $(OBJS)
