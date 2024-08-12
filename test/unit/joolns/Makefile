MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

UNIT = joolns

obj-m += $(UNIT).o

$(UNIT)-objs += ../../../src/common/types.o
$(UNIT)-objs += ../../../src/mod/common/types.o
$(UNIT)-objs += ../../../src/mod/common/address.o
$(UNIT)-objs += ../framework/unit_test.o
$(UNIT)-objs += ../../../src/common/config.o
$(UNIT)-objs += ../../../src/mod/common/atomic_config.o
#$(UNIT)-objs += ../../../src/mod/common/wrapper-global.o
$(UNIT)-objs += ../../../src/mod/common/rtrie.o
$(UNIT)-objs += ../../../src/mod/common/stats.o
$(UNIT)-objs += ../../../src/mod/common/xlator.o
$(UNIT)-objs += ../../../src/mod/common/db/global.o
$(UNIT)-objs += ../../../src/mod/common/db/denylist4.o
$(UNIT)-objs += ../../../src/mod/common/db/pool.o
$(UNIT)-objs += ../../../src/mod/common/db/eam.o
$(UNIT)-objs += ../impersonator/nat64.o
$(UNIT)-objs += ../impersonator/nf_hook.o
$(UNIT)-objs += ../impersonator/send_packet.o
$(UNIT)-objs += impersonator.o
$(UNIT)-objs += joolns_test.o

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
