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
	# Don't need this noise.
	sudo dmesg -c > /dev/null

	# Insert the dependencies.
	sudo modprobe nf_defrag_ipv6
	sudo modprobe nf_defrag_ipv4
	
	# Tell the kernel we know a route to the NAT64 prefix
	# so it doesn't drop packets prematurely.
	sudo ip link add nat64 type dummy
	sudo ip link set nat64 up
	sudo ip -6 route add 64:ff9b::/96 dev nat64
	
	# Enable forwarding.
	sudo sysctl -w net.ipv4.conf.all.forwarding=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1
	
	# Insert and configure Jool a little bit.
	sudo insmod jool.ko pool4=192.0.2.2
	sudo ../usr/src/jool --minMTU6=1500
	dmesg | tail -15

remove:
	-sudo ip link del nat64
	-sudo rmmod jool
	-sudo modprobe -r nf_defrag_ipv6
	-sudo modprobe -r nf_defrag_ipv4
	dmesg | tail -15
