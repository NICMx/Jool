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
	rm -f ../stateful/bib/*.o
	rm -f ../stateful/pool4/*.o
	rm -f ../stateful/session/*.o
debug:
	make all JOOL_FLAGS+=-DDEBUG

# The targets below are meant for quick testing.
# If you want to install the module, see ../INSTALL.

insert:
	# Don't need this noise.
	sudo dmesg -C

	# Insert the dependencies.
	sudo modprobe nf_defrag_ipv6
	sudo modprobe nf_defrag_ipv4

	# Insert and configure Jool a little bit.
	sudo insmod jool.ko pool6=64:ff9b::/96
	sudo ../../usr/stateful/jool -4a 192.0.2.2 1-3000
	sudo ../../usr/stateful/jool -batu 192.0.2.2#2000 2001:db8::5#2000
	sudo ../../usr/stateful/jool -bai 192.0.2.2#1 2001:db8::5#1
	dmesg

remove:
	-sudo rmmod jool.ko
	-sudo modprobe -r nf_defrag_ipv6
	-sudo modprobe -r nf_defrag_ipv4
	dmesg | tail -1
again:
	sudo modprobe -r jool
	make debug
	sudo make modules_install
	sudo modprobe jool pool6=64:ff9b::/96
	sudo jool -bat 1::5#65000 192.0.2.1#65000
	sudo jool --address-dependent-filtering 1
	sudo dmesg -C
