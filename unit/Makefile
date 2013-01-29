MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m += rfc6052.o hashtable.o pool4.o bib_session.o iterator.o outgoing.o translate.o

rfc6052-objs += ../mod/nf_nat64_types.o
rfc6052-objs += unit_test.o
rfc6052-objs += nf_nat64_rfc6052_test.o

hashtable-objs += ../mod/nf_nat64_types.o
hashtable-objs += unit_test.o
hashtable-objs += nf_nat64_hash_table_test.o

pool4-objs += ../mod/nf_nat64_types.o
pool4-objs += unit_test.o
pool4-objs += nf_nat64_pool_test.o

bib_session-objs += ../mod/nf_nat64_types.o
bib_session-objs += ../mod/nf_nat64_bib.o
bib_session-objs += ../mod/nf_nat64_session.o
bib_session-objs += unit_test.o
bib_session-objs += nf_nat64_bib_session_test.o

iterator-objs += ../mod/nf_nat64_types.o
iterator-objs += unit_test.o
iterator-objs += nf_nat64_ipv6_hdr_iterator_test.o

outgoing-objs += ../mod/nf_nat64_types.o
outgoing-objs += ../mod/nf_nat64_rfc6052.o
outgoing-objs += ../mod/nf_nat64_pool6.o
outgoing-objs += ../mod/nf_nat64_bib.o
outgoing-objs += unit_test.o
outgoing-objs += nf_nat64_outgoing_test.o

translate-objs += ../mod/nf_nat64_types.o
translate-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
translate-objs += unit_test.o
translate-objs += nf_nat64_translate_packet_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	sudo insmod rfc6052.ko
	sudo rmmod rfc6052
	sudo insmod hashtable.ko
	sudo rmmod hashtable
	#sudo insmod pool.ko
	#sudo rmmod pool
	sudo insmod bib_session.ko
	sudo rmmod bib_session
	sudo insmod iterator.ko
	sudo rmmod iterator
	sudo insmod outgoing.ko
	sudo rmmod outgoing
	sudo insmod translate.ko
	sudo rmmod translate
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f ../mod/*.o
