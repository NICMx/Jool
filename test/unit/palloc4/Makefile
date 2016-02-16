MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING
EXTRA_CFLAGS += -DBENCHMARK

#CC=cgcc
ccflags-y := -I$(src)/../../../include
ccflags-y += -I$(src)/../../../mod/common
ccflags-y += -I$(src)/../../../mod/stateful
ccflags-y += -I$(src)/../../../mod/stateless

PALLOC = palloc4

obj-m += $(PALLOC).o

MIN_REQS = ../../../mod/common/types.o \
	../../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o

$(PALLOC)-objs += $(MIN_REQS)
$(PALLOC)-objs += ../../../mod/common/config.o
$(PALLOC)-objs += ../../../mod/common/ipv6_hdr_iterator.o
$(PALLOC)-objs += ../../../mod/common/pool6.o
$(PALLOC)-objs += ../../../mod/common/rfc6052.o
$(PALLOC)-objs += ../../../mod/common/rfc6145/common.o
$(PALLOC)-objs += ../../../mod/common/rfc6145/4to6.o
$(PALLOC)-objs += ../../../mod/common/rfc6145/6to4.o
$(PALLOC)-objs += ../../../mod/stateful/impersonator.o
$(PALLOC)-objs += ../../../mod/stateful/pool4/db.o
$(PALLOC)-objs += ../../../mod/stateful/pool4/empty.o
$(PALLOC)-objs += ../../../mod/stateful/pool4/entry.o
$(PALLOC)-objs += ../../../mod/stateful/pool4/table.o
$(PALLOC)-objs += ../framework/types.o
$(PALLOC)-objs += ../impersonator/bib.o
$(PALLOC)-objs += ../impersonator/icmp_wrapper.o
$(PALLOC)-objs += ../impersonator/route.o
$(PALLOC)-objs += port_allocator_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(PALLOC).ko && sudo rmmod $(PALLOC)
	sudo dmesg -c | less
