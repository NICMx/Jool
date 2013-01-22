MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


obj-m += nat64.o

#nat64-objs += ../unit/unit_test.o
nat64-objs += ../mod/nf_nat64_types.o
nat64-objs += ../mod/nf_nat64_rfc6052.o
nat64-objs += ../mod/nf_nat64_bib.o
nat64-objs += ../mod/nf_nat64_session.o
nat64-objs += ../mod/nf_nat64_ipv6_hdr_iterator.o
nat64-objs += ../mod/nf_nat64_config.o
nat64-objs += ../mod/xt_nat64_module_conf_validation.o
nat64-objs += ../mod/xt_nat64_config_proto.o
nat64-objs += ../mod/nf_nat64_pool6.o
nat64-objs += ../mod/nf_nat64_ipv4_pool.o
nat64-objs += ../mod/nf_nat64_static_routes.o
nat64-objs += ../mod/nf_nat64_determine_incoming_tuple.o
#nat64-objs += ../mod/nf_nat64_filtering_and_updating.o
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
