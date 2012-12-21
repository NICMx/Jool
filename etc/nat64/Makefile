CC = gcc
LD = ld

INCDIRS += -Iinclude -I../../include
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
OBJS := validation.o types.o nat64.o


nat64: $(OBJS)
	$(CC) -o $@ $(LDLIBS) $(OBJS)

validation.o: ../../mod/xt_nat64_module_conf_validation.c
	$(CC) -c $(CFLAGS) $< -o $@

types.o: ../../mod/nf_nat64_types.c
	$(CC) -c $(CFLAGS) $< -o $@

nat64.o: nat64.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(PROGS) $(OBJS)
