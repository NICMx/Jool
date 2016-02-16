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


TRANSLATE = translate

obj-m += $(TRANSLATE).o

MIN_REQS = ../../../mod/common/types.o \
	../../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o

$(TRANSLATE)-objs += $(MIN_REQS)
$(TRANSLATE)-objs += ../../../mod/common/config.o
$(TRANSLATE)-objs += ../../../mod/common/ipv6_hdr_iterator.o
$(TRANSLATE)-objs += ../../../mod/common/packet.o
$(TRANSLATE)-objs += ../../../mod/common/pool6.o
$(TRANSLATE)-objs += ../../../mod/common/rfc6052.o
$(TRANSLATE)-objs += ../../../mod/common/rfc6145/common.o
$(TRANSLATE)-objs += ../../../mod/stateful/impersonator.o
$(TRANSLATE)-objs += ../framework/skb_generator.o
$(TRANSLATE)-objs += ../framework/types.o
$(TRANSLATE)-objs += ../impersonator/icmp_wrapper.o
$(TRANSLATE)-objs += translate_packet_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(TRANSLATE).ko && sudo rmmod $(TRANSLATE)
	sudo dmesg -c | less
