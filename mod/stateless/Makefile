MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build

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
	rm -f ../common/*.o
	rm -f ../common/rfc6145/*.o
debug:
	make all JOOL_FLAGS+=-DDEBUG

# The targets below are meant for quick testing.
# If you want to install the module, see ../INSTALL.

insert:
	sudo dmesg -C
	sudo insmod jool_siit.ko
	dmesg

remove:
	-sudo rmmod jool_siit.ko
	dmesg | tail -1
again:
	sudo rmmod jool_siit
	make
	sudo insmod jool_siit.ko disabled