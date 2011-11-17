#!/bin/bash

IPV4_ADDR="192.168.56.2"
PREFIX_ADDR="fec0::"
PREFIX_LEN="64"

if [ $1 = "ins" ] ; then
	sudo modprobe ipv6
	sudo modprobe ip_tables
	sudo modprobe nf_conntrack
	sudo modprobe nf_conntrack_ipv4
	sudo ip6tables -t mangle --flush
	sudo insmod nat64.ko nat64_ipv4_addr=$IPV4_ADDR nat64_prefix_addr=$PREFIX_ADDR nat64_prefix_len=$PREFIX_LEN

	# Enable the nat64 network interface
	sudo ifconfig nat64 up

	# Install the route to the nat64 prefix
	sudo ip -6 route add ${PREFIX_ADDR}/${PREFIX_LEN} dev nat64

	# Enable ipv6 and ipv4 forwarding
	sudo sysctl -w net.ipv4.conf.all.forwarding=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1
	
	echo "installed the NAT64 module"
elif [ $1 = "rmv" ] ; then
	sudo ip6tables -t mangle --flush
	sudo ip -6 route del ${PREFIX_ADDR}/${PREFIX_LEN} dev nat64
	sudo ifconfig nat64 down
	sudo rmmod nat64.ko
	echo "removed the NAT64 module"
elif [ $1 = "debug" ] ; then
	sudo dmesg | tail -30
elif [ $1 = "test" ] ; then
	sudo ip6tables -t mangle --flush
	sudo ip6tables -t mangle -A PREROUTING -j nat64 --ipdst fec0::/64 --outdev eth0
	sudo ip6tables -t mangle -n -L
	sudo ping6 ::1
elif [ $1 = "setup" ] ; then
	sudo ./workflow.sh "ins"
	sudo ./workflow.sh "test"
	sudo ./workflow.sh "rmv"
	sudo ./workflow.sh "ins"
else
	echo "no valid action selected" 
fi
