MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m += rfc6052.o hashtable.o pool4.o iterator.o bib_session.o
obj-m += filtering.o outgoing.o translate.o

rfc6052-objs += ../mod/types.o
rfc6052-objs += ../mod/str_utils.o
rfc6052-objs += unit_test.o
rfc6052-objs += rfc6052_test.o

hashtable-objs += ../mod/types.o
hashtable-objs += unit_test.o
hashtable-objs += hash_table_test.o

pool4-objs += ../mod/types.o
pool4-objs += ../mod/str_utils.o
pool4-objs += unit_test.o
pool4-objs += pool4_test.o

bib_session-objs += ../mod/types.o
bib_session-objs += ../mod/str_utils.o
bib_session-objs += ../mod/rfc6052.o
bib_session-objs += ../mod/pool6.o
bib_session-objs += ../mod/pool4.o
bib_session-objs += ../mod/bib.o
bib_session-objs += ../mod/filtering_and_updating.o
bib_session-objs += ../mod/send_packet.o
bib_session-objs += unit_test.o
bib_session-objs += bib_session_test.o

iterator-objs += ../mod/types.o
iterator-objs += unit_test.o
iterator-objs += ipv6_hdr_iterator_test.o

filtering-objs += ../mod/types.o
filtering-objs += ../mod/str_utils.o
filtering-objs += ../mod/ipv6_hdr_iterator.o
filtering-objs += ../mod/rfc6052.o
filtering-objs += ../mod/pool6.o
filtering-objs += ../mod/pool4.o
filtering-objs += ../mod/bib.o
filtering-objs += ../mod/session.o
filtering-objs += ../mod/static_routes.o
filtering-objs += ../mod/config.o
filtering-objs += ../mod/config_proto.o
filtering-objs += ../mod/translate_packet.o
filtering-objs += ../mod/send_packet.o
filtering-objs += unit_test.o
filtering-objs += filtering_and_updating_test.o

outgoing-objs += ../mod/types.o
outgoing-objs += ../mod/str_utils.o
outgoing-objs += ../mod/rfc6052.o
outgoing-objs += ../mod/pool6.o
outgoing-objs += ../mod/bib.o
outgoing-objs += unit_test.o
outgoing-objs += compute_outgoing_tuple_test.o

translate-objs += ../mod/types.o
translate-objs += ../mod/ipv6_hdr_iterator.o
translate-objs += unit_test.o
translate-objs += translate_packet_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod rfc6052.ko
	-sudo rmmod rfc6052
	-sudo insmod hashtable.ko
	-sudo rmmod hashtable
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
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f ../mod/*.o
