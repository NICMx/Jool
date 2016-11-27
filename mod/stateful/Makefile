MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f ../common/*.o
	rm -f ../common/rfc6145/*.o
debug:
	make -C ${KERNEL_DIR} M=$$PWD JOOL_DEBUG=-DDEBUG;

# The targets below are meant for quick testing.
# If you want to install the module, see ../INSTALL.

insert:
	# Don't need this noise.
	sudo dmesg -C

	# Insert the dependencies.
	sudo modprobe nf_defrag_ipv6
	sudo modprobe nf_defrag_ipv4

	# Enable forwarding.
	sudo sysctl -w net.ipv4.conf.all.forwarding=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1

	# Insert and configure Jool a little bit.
	sudo insmod jool.ko pool4=192.0.2.2 pool6=64:ff9b::/96
	sudo ../../usr/stateful/jool -batu 192.0.2.2#2000 2001:db8::5#2000
	sudo ../../usr/stateful/jool -bai 192.0.2.2#1 2001:db8::5#1
	dmesg

remove:
	-sudo rmmod jool.ko
	-sudo modprobe -r nf_defrag_ipv6
	-sudo modprobe -r nf_defrag_ipv4
	dmesg | tail -1
