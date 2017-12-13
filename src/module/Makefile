MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

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

# Debug targets
insert:
	sudo insmod jool.ko
	sudo ip link set jool0 up
	sudo ip addr add 2001:db8::1/96 dev jool0
remove:
	sudo rmmod jool
