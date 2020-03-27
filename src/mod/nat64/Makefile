MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build
KBUILD_EXTRA_SYMBOLS = $(src)/../common/Module.symvers

#CC=cgcc    # More healthy warnings.
ccflags-y := -I$(src)/../.. $(JOOL_FLAGS)

obj-m += jool.o

all:
	make -C ${KERNEL_DIR} M=$$PWD JOOL_FLAGS="${JOOL_FLAGS}"
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@
install: modules_install
	depmod
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@
debug:
	make all JOOL_FLAGS+=-DDEBUG
