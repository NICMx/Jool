MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m += test.o

# Translate packet
#test-objs += ../mod/types.o
#test-objs += ../mod/str_utils.o
#test-objs += ../mod/packet.o
#test-objs += ../mod/ipv6_hdr_iterator.o
#test-objs += framework/unit_test.o
#test-objs += framework/skb_generator.o
#test-objs += framework/validator.o
#test-objs += tp_test.o

# Packet
test-objs += ../mod/types.o
test-objs += ../mod/str_utils.o
test-objs += ../mod/ipv6_hdr_iterator.o
test-objs += ../mod/packet.o
test-objs += framework/unit_test.o
test-objs += framework/skb_generator.o
test-objs += framework/validator.o
test-objs += packet_db_test.o

# Impresión de tamaños
#test-objs += packet_test.o



all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod rfc6052.ko
	-sudo rmmod rfc6052
	-sudo insmod hashtable.ko
	-sudo rmmod hashtable
	-sudo insmod poolnum.ko
	-sudo rmmod poolnum
	-sudo insmod pool4.ko
	-sudo rmmod pool4
	-sudo insmod bib_session.ko
	-sudo rmmod bib_session
	-sudo insmod iterator.ko
	-sudo rmmod iterator
	-sudo insmod filtering.ko
	-sudo rmmod filtering
	-sudo insmod outgoing.ko
	-sudo rmmod outgoing
	-sudo insmod translate.ko
	-sudo rmmod translate
	-sudo insmod hairpinning.ko
	-sudo rmmod hairpinning
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f ../mod/*.o
