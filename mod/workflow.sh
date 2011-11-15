#!/bin/bash

if [ $1 = "ins" ] ; then
	sudo modprobe ipv6
	sudo modprobe ip_tables
	sudo modprobe nf_conntrack
	sudo modprobe nf_conntrack_ipv4
	sudo ip6tables -t mangle --flush
	sudo insmod nat64.ko
	echo "installed the NAT64 module"
elif [ $1 = "rmv" ] ; then
	sudo ip6tables -t mangle --flush
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
