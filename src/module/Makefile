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
	sudo ip addr add 2001:db8::8/96 dev jool0
	sudo ip addr add 192.0.2.8/24 dev jool0
	sudo ip -6 route add 64:ff9b::/96 via 2001:db8::1
remove:
	sudo rmmod jool
again:
	-sudo make remove
	make debug
	sudo dmesg -C
	sudo make insert
