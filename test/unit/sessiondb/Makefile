MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING
EXTRA_CFLAGS += -DBENCHMARK

#CC=cgcc
ccflags-y := -I$(src)/../../include
ccflags-y += -I$(src)/../../mod/common
ccflags-y += -I$(src)/../../mod/stateful
ccflags-y += -I$(src)/../../mod/stateless

SESSIONDB = sessiondb

obj-m += $(SESSIONDB).o

MIN_REQS = ../../mod/common/types.o \
	../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o

$(SESSIONDB)-objs += $(MIN_REQS)
$(SESSIONDB)-objs += ../../mod/common/config.o
$(SESSIONDB)-objs += ../../mod/common/rbtree.o
$(SESSIONDB)-objs += ../../mod/stateful/session/entry.o
$(SESSIONDB)-objs += ../../mod/stateful/session/table.o
$(SESSIONDB)-objs += ../../mod/stateful/session/pkt_queue.o
$(SESSIONDB)-objs += ../framework/session.o
$(SESSIONDB)-objs += ../impersonator/bib.o
$(SESSIONDB)-objs += ../impersonator/icmp_wrapper.o
$(SESSIONDB)-objs += ../impersonator/route.o
$(SESSIONDB)-objs += sessiondb_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
