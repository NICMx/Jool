MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;

# The targets below are meant for quick testing.
# If you want to install the module, see ../INSTALL.

insert:
	# insert the dependencies
	sudo modprobe ipv6
	# enable ipv6 and ipv4 forwarding
	sudo sysctl -w net.ipv4.conf.all.forwarding=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1
	# insert the module
	sudo insmod jool.ko pool4=192.0.2.2
	dmesg | tail -15
	sudo ../usr/src/jool --minMTU6=1500

remove:
	sudo rmmod jool
	dmesg | tail -15
