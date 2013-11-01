MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
# If it won't compile, install sparse or comment this line.
CC=cgcc

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
	# prevent martian packets from reaching the module
	sudo sysctl -w net.ipv4.conf.all.log_martians=1
	# insert the module
	sudo insmod jool.ko
	dmesg | tail -15
	../usr/jool -z --minMTU6=1500
remove:
	sudo rmmod jool
	dmesg | tail -15
