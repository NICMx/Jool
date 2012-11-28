MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -I$(src)/../mod
EXTRA_CFLAGS += -I$(src)/../include


obj-m += rfc6052.o hashtable.o bib_session.o outgoing.o translate.o iterator.o core.o

rfc6052-objs += ../mod/nf_nat64_rfc6052.o
rfc6052-objs += ../unit/nf_nat64_rfc6052_test.o

hashtable-objs += ../unit/nf_nat64_hash_table_test.o

bib_session-objs += ../mod/nf_nat64_types.o
bib_session-objs += ../mod/nf_nat64_bib.o
bib_session-objs += ../mod/nf_nat64_session.o
bib_session-objs += ../unit/nf_nat64_bib_session_test.o

iterator-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
iterator-objs += ../unit/nf_nat64_ipv6_hdr_iterator_test.o

outgoing-objs += ../mod/nf_nat64_types.o
outgoing-objs += ../mod/nf_nat64_rfc6052.o
outgoing-objs += ../mod/nf_nat64_bib.o
outgoing-objs += ../unit/nf_nat64_outgoing_test.o

translate-objs += ../mod/external_stuff.o
translate-objs += ../mod/nf_nat64_types.o
translate-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
translate-objs += ../unit/nf_nat64_translate_packet_test.o

core-objs += ../mod/external_stuff.o
core-objs += ../mod/nf_nat64_types.o
core-objs += ../mod/nf_nat64_rfc6052.o
core-objs += ../mod/nf_nat64_bib.o
core-objs += ../mod/nf_nat64_session.o
core-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
core-objs += ../mod/nf_nat64_determine_incoming_tuple.o
core-objs += ../mod/nf_nat64_outgoing.o
core-objs += ../mod/nf_nat64_translate_packet.o
core-objs += ../mod/xt_nat64_core.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
insert:
	# insert the dependencies
	sudo modprobe ipv6
	sudo modprobe ip_tables
	sudo modprobe nf_conntrack
	sudo modprobe nf_conntrack_ipv4
	# insert the module
	sudo insmod core.ko
	dmesg | tail -15
	# insert the rule
	sudo iptables -t mangle --flush
	sudo ip6tables -t mangle --flush
	sudo iptables -t mangle -A PREROUTING -j NAT64
	sudo ip6tables -t mangle -A PREROUTING -j NAT64
remove:
	# remove the rule
	sudo iptables -t mangle --flush
	sudo ip6tables -t mangle --flush
	# remove the module
	sudo rmmod core
	dmesg | tail -15
test:
	sudo insmod rfc6052.ko
	sudo rmmod rfc6052
	sudo insmod hashtable.ko
	sudo rmmod hashtable
	sudo insmod bib_session.ko
	sudo rmmod bib_session
	sudo insmod iterator.ko
	sudo rmmod iterator
	sudo insmod outgoing.ko
	sudo rmmod outgoing
	sudo insmod translate.ko
	sudo rmmod translate
	dmesg | grep 'Finished. Runs: '
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm *.o *.ko *.mod.c modules.order ../mod/*.o ../unit/*.o
