MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
CC=cgcc

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m += packet.o packetdb.o outgoing.o translate.o send.o


# Packet
packet-objs += ../mod/types.o
packet-objs += ../mod/str_utils.o
packet-objs += ../mod/ipv6_hdr_iterator.o
packet-objs += ../mod/packet.o
packet-objs += framework/unit_test.o
packet-objs += packet_test.o

# Packet DB
packetdb-objs += ../mod/types.o
packetdb-objs += ../mod/str_utils.o
packetdb-objs += ../mod/ipv6_hdr_iterator.o
packetdb-objs += ../mod/packet.o
packetdb-objs += framework/unit_test.o
packetdb-objs += framework/skb_generator.o
packetdb-objs += framework/validator.o
packetdb-objs += framework/types.o
packetdb-objs += packet_db_test.o

# Computing the Outgoing Tuple
outgoing-objs += ../mod/types.o
outgoing-objs += ../mod/str_utils.o
outgoing-objs += ../mod/packet.o
outgoing-objs += ../mod/ipv6_hdr_iterator.o
outgoing-objs += ../mod/rfc6052.o
outgoing-objs += ../mod/pool6.o
outgoing-objs += ../mod/bib.o
outgoing-objs += framework/unit_test.o
outgoing-objs += compute_outgoing_tuple_test.o

# Translating the Packet
translate-objs += ../mod/types.o
translate-objs += ../mod/str_utils.o
translate-objs += ../mod/packet.o
translate-objs += ../mod/ipv6_hdr_iterator.o
translate-objs += ../mod/send_packet.o
translate-objs += framework/unit_test.o
translate-objs += framework/skb_generator.o
translate-objs += framework/validator.o
translate-objs += framework/types.o
translate-objs += translate_packet_test.o

# Send packet (does not have a unit test, so just make sure it compiles.)
send-objs += ../mod/send_packet.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod packet.ko
	-sudo rmmod packet
	-sudo insmod packetdb.ko
	-sudo rmmod packetdb
	#-sudo insmod iterator.ko
	#-sudo rmmod iterator
	#-sudo insmod rfc6052.ko
	#-sudo rmmod rfc6052
	#-sudo insmod hashtable.ko
	#-sudo rmmod hashtable
	#-sudo insmod poolnum.ko
	#-sudo rmmod poolnum
	#-sudo insmod pool4.ko
	#-sudo rmmod pool4
	#-sudo insmod bib_session.ko
	#-sudo rmmod bib_session
	#-sudo insmod filtering.ko
	#-sudo rmmod filtering
	-sudo insmod outgoing.ko
	-sudo rmmod outgoing
	-sudo insmod translate.ko
	-sudo rmmod translate
	#-sudo insmod hairpinning.ko
	#-sudo rmmod hairpinning
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  ../mod/*.o  *.ko  *.o
