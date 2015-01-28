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
	rm -f ../common/*.o
	rm -f ../common/rfc6145/*.o

# The targets below are meant for quick testing.
# If you want to install the module, see ../INSTALL.

insert:
	# Don't need this noise.
	sudo dmesg -C

	# Enable forwarding.
	sudo sysctl -w net.ipv4.conf.all.forwarding=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1

	# Insert and configure Jool a little bit.
	sudo insmod jool_stateless.ko pool4=192.0.2.128/25 pool6=2001:db8:100::/40
	dmesg | tail -15

remove:
	-sudo rmmod jool_stateless.ko
	dmesg | tail -15
