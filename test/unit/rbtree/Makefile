KERNEL_DIR := /lib/modules/$(shell uname -r)/build
KBUILD_EXTRA_SYMBOLS  = $(src)/../../../src/mod/common/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(src)/../framework/Module.symvers
ccflags-y += -I$(src)/../../../src -I$(src)/..

UNIT = rbtree_test

obj-m += $(UNIT).o

all:
	make -C $(KERNEL_DIR) M=$$PWD;
modules:
	make -C $(KERNEL_DIR) M=$$PWD $@;
clean:
	make -C $(KERNEL_DIR) M=$$PWD $@;
test:
	sudo dmesg -C
	sudo modprobe jool_common
	sudo insmod ../framework/unit.ko
	-sudo insmod $(UNIT).ko && sudo rmmod $(UNIT)
	sudo rmmod unit.ko
	sudo modprobe -r jool_common
	sudo dmesg -t | less
