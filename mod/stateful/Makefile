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
	rm -f ../common/*.o
	rm -f ../common/rfc6145/*.o
	rm -f ../stateful/bib/*.o
	rm -f ../stateful/pool4/*.o
	rm -f ../stateful/session/*.o
debug:
	make all JOOL_FLAGS+=-DDEBUG

# The targets below are meant for quick testing.
# If you want to install the module, see ../INSTALL.

again:
	sudo modprobe -r jool
	make debug
	sudo make modules_install
	sudo modprobe jool pool6=64:ff9b::/96
	sudo jool -batu 1::5#65000 192.0.2.1#65000
	#sudo jool --address-dependent-filtering on
	sudo dmesg -C
quick:
	sudo modprobe -r jool
	sudo modprobe jool pool6=64:ff9b::/96
	sudo jool -batu 1::5#65000 192.0.2.1#65000
	#sudo jool --address-dependent-filtering on
	sudo dmesg -C
