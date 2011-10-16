#!/bin/bash

if [ $1 = "ins" ] ; then
	sudo modprobe ipv6
	sudo modprobe ip_tables
	sudo modprobe nf_conntrack
	sudo modprobe nf_conntrack_ipv4
	sudo ip6tables -t mangle --flush
	sudo insmod xt_nat64.ko
	echo "installed the NAT64 module"
elif [ $1 = "rmv" ] ; then
	sudo ip6tables -t mangle --flush
	sudo rmmod xt_nat64.ko
	echo "removed the NAT64 module"
elif [ $1 = "debug" ] ; then
	sudo dmesg | tail -30
elif [ $1 = "test" ] ; then
	sudo ip6tables -t mangle --flush
	sudo ip6tables -t mangle -A PREROUTING -j nat64 --ipdst ::1/64;
	sudo ip6tables -t mangle -n -L
	sudo ping6 ::1
else
	echo "no valid action selected" 
fi
