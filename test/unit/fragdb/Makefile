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


FRAGDB = fragdb

obj-m += $(FRAGDB).o

MIN_REQS = ../../mod/common/types.o \
	../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o


$(FRAGDB)-objs += $(MIN_REQS)
$(FRAGDB)-objs += ../../mod/common/config.o
$(FRAGDB)-objs += ../../mod/common/ipv6_hdr_iterator.o
$(FRAGDB)-objs += ../../mod/common/packet.o
$(FRAGDB)-objs += ../framework/skb_generator.o
$(FRAGDB)-objs += ../framework/types.o
$(FRAGDB)-objs += fragment_db_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
