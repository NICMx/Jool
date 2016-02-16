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

FILTERING = filtering

obj-m += $(FILTERING).o

MIN_REQS = ../../../mod/common/types.o \
	../../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o


$(FILTERING)-objs += $(MIN_REQS)
$(FILTERING)-objs += ../../../mod/common/atomic_config.o
$(FILTERING)-objs += ../../../mod/common/config.o
$(FILTERING)-objs += ../../../mod/common/ipv6_hdr_iterator.o
$(FILTERING)-objs += ../../../mod/common/packet.o
$(FILTERING)-objs += ../../../mod/common/pool6.o
$(FILTERING)-objs += ../../../mod/common/rbtree.o
$(FILTERING)-objs += ../../../mod/common/rfc6052.o
$(FILTERING)-objs += ../../../mod/common/xlator.o
$(FILTERING)-objs += ../../../mod/common/nl/nl_common.o
$(FILTERING)-objs += ../../../mod/common/nl/nl_core2.o
$(FILTERING)-objs += ../../../mod/common/rfc6145/4to6.o
$(FILTERING)-objs += ../../../mod/common/rfc6145/6to4.o
$(FILTERING)-objs += ../../../mod/common/rfc6145/common.o
$(FILTERING)-objs += ../../../mod/stateful/fragment_db.o
$(FILTERING)-objs += ../../../mod/stateful/impersonator.o
$(FILTERING)-objs += ../../../mod/stateful/joold.o
$(FILTERING)-objs += ../../../mod/stateful/pool4/entry.o
$(FILTERING)-objs += ../../../mod/stateful/pool4/table.o
$(FILTERING)-objs += ../../../mod/stateful/pool4/db.o
$(FILTERING)-objs += ../../../mod/stateful/bib/table.o
$(FILTERING)-objs += ../../../mod/stateful/bib/db.o
$(FILTERING)-objs += ../../../mod/stateful/bib/port_allocator.o
$(FILTERING)-objs += ../../../mod/stateful/session/entry.o
$(FILTERING)-objs += ../../../mod/stateful/session/table.o
$(FILTERING)-objs += ../../../mod/stateful/session/db.o
$(FILTERING)-objs += ../../../mod/stateful/session/pkt_queue.o
$(FILTERING)-objs += ../framework/skb_generator.o
$(FILTERING)-objs += ../framework/types.o
$(FILTERING)-objs += ../impersonator/icmp_wrapper.o
$(FILTERING)-objs += ../impersonator/nl.o
$(FILTERING)-objs += ../impersonator/pool4_empty.o
$(FILTERING)-objs += ../impersonator/route.o
$(FILTERING)-objs += filtering_and_updating_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(FILTERING).ko && sudo rmmod $(FILTERING)
	sudo dmesg -c | less
