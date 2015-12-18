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


SESSIONTABLE = sessiontable

obj-m += $(SESSIONTABLE).o

MIN_REQS = ../../mod/common/types.o \
	../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o

$(SESSIONTABLE)-objs += $(MIN_REQS)
$(SESSIONTABLE)-objs += ../../mod/common/config.o
$(SESSIONTABLE)-objs += ../../mod/common/rbtree.o
$(SESSIONTABLE)-objs += ../../mod/stateful/session/entry.o
$(SESSIONTABLE)-objs += ../../mod/stateful/session/pkt_queue.o
$(SESSIONTABLE)-objs += ../impersonator/bib.o
$(SESSIONTABLE)-objs += ../impersonator/icmp_wrapper.o
$(SESSIONTABLE)-objs += ../impersonator/route.o
$(SESSIONTABLE)-objs += sessiontable_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
