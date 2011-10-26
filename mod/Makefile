MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -I$(src)/../include
EXTRA_CFLAGS += -DDEBUG

obj-m += nat64.o 
nat64-objs := xt_nat64.o nf_nat64_tuple.o add.o nf_nat64_generic_functions.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
