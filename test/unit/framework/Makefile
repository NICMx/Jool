KERNEL_DIR := /lib/modules/$(shell uname -r)/build
KBUILD_EXTRA_SYMBOLS += $(src)/../../../src/mod/common/Module.symvers
ccflags-y += -I$(src)/../../../src -I$(src)/..
EXTRA_CFLAGS += -DUNIT_TESTING


obj-m += unit.o
unit-objs += bib.o
unit-objs += skb_generator.o
unit-objs += types.o
unit-objs += unit_test.o


all:
	make -C $(KERNEL_DIR) M=$$PWD;
modules:
	make -C $(KERNEL_DIR) M=$$PWD $@;
clean:
	make -C $(KERNEL_DIR) M=$$PWD $@;
