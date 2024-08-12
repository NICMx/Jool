MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

UNIT = pkt

obj-m += $(UNIT).o

$(UNIT)-objs += ../../../src/common/types.o
$(UNIT)-objs += ../../../src/mod/common/types.o
$(UNIT)-objs += ../../../src/mod/common/address.o
$(UNIT)-objs += ../framework/unit_test.o
$(UNIT)-objs += ../../../src/mod/common/packet.o
$(UNIT)-objs += ../../../src/mod/common/translation_state.o
$(UNIT)-objs += ../framework/skb_generator.o
$(UNIT)-objs += ../impersonator/stats.o
$(UNIT)-objs += packet_test.o

EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING
ccflags-y := -I$(src)/../../../src -I$(src)/..

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	-sudo insmod $(UNIT).ko && sudo rmmod $(UNIT)
	sudo dmesg -tc | less
