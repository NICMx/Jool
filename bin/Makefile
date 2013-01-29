MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m += rfc6052.o hashtable.o pool.o bib_session.o iterator.o outgoing.o translate.o filtering_and_updating.o nat64.o

rfc6052-objs += ../mod/nf_nat64_types.o
rfc6052-objs += ../mod/nf_nat64_rfc6052.o
rfc6052-objs += ../unit/unit_test.o
rfc6052-objs += ../unit/nf_nat64_rfc6052_test.o

hashtable-objs += ../mod/nf_nat64_types.o
hashtable-objs += ../unit/unit_test.o
hashtable-objs += ../unit/nf_nat64_hash_table_test.o

pool-objs += ../mod/nf_nat64_types.o
pool-objs += ../mod/nf_nat64_config.o
pool-objs += ../mod/nf_nat64_ipv4_pool.o
pool-objs += ../mod/nf_nat64_bib.o
pool-objs += ../mod/nf_nat64_session.o
pool-objs += ../mod/nf_nat64_static_routes.o
pool-objs += ../unit/unit_test.o
pool-objs += ../unit/nf_nat64_pool_test.o

bib_session-objs += ../mod/nf_nat64_types.o
bib_session-objs += ../mod/nf_nat64_bib.o
bib_session-objs += ../mod/nf_nat64_session.o
bib_session-objs += ../unit/unit_test.o
bib_session-objs += ../unit/nf_nat64_bib_session_test.o

iterator-objs += ../mod/nf_nat64_types.o
iterator-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
iterator-objs += ../unit/unit_test.o
iterator-objs += ../unit/nf_nat64_ipv6_hdr_iterator_test.o

outgoing-objs += ../mod/nf_nat64_types.o
outgoing-objs += ../mod/nf_nat64_rfc6052.o
outgoing-objs += ../mod/nf_nat64_bib.o
outgoing-objs += ../unit/unit_test.o
outgoing-objs += ../unit/nf_nat64_outgoing_test.o

translate-objs += ../mod/external_stuff.o
translate-objs += ../mod/nf_nat64_types.o
translate-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
translate-objs += ../mod/nf_nat64_bib.o
translate-objs += ../mod/nf_nat64_session.o
translate-objs += ../mod/nf_nat64_static_routes.o
translate-objs += ../mod/nf_nat64_config.o
translate-objs += ../unit/unit_test.o
translate-objs += ../unit/nf_nat64_translate_packet_test.o

filtering_and_updating-objs += ../mod/nf_nat64_send_packet.o
filtering_and_updating-objs += ../mod/nf_nat64_rfc6052.o
filtering_and_updating-objs += ../mod/nf_nat64_static_routes.o
filtering_and_updating-objs += ../mod/nf_nat64_ipv4_pool.o
filtering_and_updating-objs += ../mod/nf_nat64_bib.o
filtering_and_updating-objs += ../mod/nf_nat64_session.o
filtering_and_updating-objs += ../mod/nf_nat64_types.o
filtering_and_updating-objs += ../mod/nf_nat64_config.o
filtering_and_updating-objs += ../mod/xt_nat64_module_conf_validation.o
filtering_and_updating-objs += ../mod/nf_nat64_filtering_and_updating.o

nat64-objs += ../mod/external_stuff.o
nat64-objs += ../mod/nf_nat64_types.o
nat64-objs += ../mod/nf_nat64_rfc6052.o
nat64-objs += ../mod/nf_nat64_bib.o
nat64-objs += ../mod/nf_nat64_session.o
nat64-objs += ../mod/nf_nat64_ipv4_pool.o
nat64-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
nat64-objs += ../mod/nf_nat64_config.o
nat64-objs += ../mod/xt_nat64_module_conf_validation.o
nat64-objs += ../mod/nf_nat64_static_routes.o
nat64-objs += ../mod/nf_nat64_determine_incoming_tuple.o
nat64-objs += ../mod/nf_nat64_filtering_and_updating.o
nat64-objs += ../mod/nf_nat64_outgoing.o
nat64-objs += ../mod/nf_nat64_translate_packet.o
nat64-objs += ../mod/nf_nat64_handling_hairpinning.o
nat64-objs += ../mod/nf_nat64_send_packet.o
nat64-objs += ../mod/xt_nat64_core.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
insert:
	# insert the dependencies
	sudo modprobe ipv6
	sudo modprobe ip_tables
	sudo modprobe nf_conntrack
	sudo modprobe nf_conntrack_ipv4
	sudo modprobe nf_conntrack_ipv6
	# enable ipv6 and ipv4 forwarding
	sudo sysctl -w net.ipv4.conf.all.forwarding=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1
	# prevent martian packets from reaching the module
	sudo sysctl -w net.ipv4.conf.all.log_martians=1
	# insert the module
	sudo insmod nat64.ko
	dmesg | tail -15
	# insert the rules
	sudo iptables -t mangle --flush
	sudo ip6tables -t mangle --flush
	sudo iptables -t mangle -A PREROUTING -j NAT64
	sudo ip6tables -t mangle -A PREROUTING -j NAT64
remove:
	# remove the rules
	sudo iptables -t mangle --flush
	sudo ip6tables -t mangle --flush
	# remove the module
	sudo rmmod nat64
	dmesg | tail -15
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
	rm -f ../mod/*.o ../unit/*.o
