#!/bin/bash

if [ $1 = "ins" ] ; then
	modprobe ipv6
	modprobe ip_tables
	modprobe nf_conntrack
	modprobe nf_conntrack_ipv4
	ip6tables -t mangle --flush
	insmod nat64.ko

	# Enable ipv6 and ipv4 forwarding
	sysctl -w net.ipv4.conf.all.forwarding=1
	sysctl -w net.ipv6.conf.all.forwarding=1

	echo "installed the NAT64 module"
elif [ $1 = "up" ] ; then
	./workflow.sh "rmv"
	./workflow.sh "ins"
	./workflow.sh "test"
elif [ $1 = "rmv" ] ; then
	ip6tables -t mangle --flush
	iptables -t mangle --flush
	rmmod nat64.ko
	echo "removed the NAT64 module"
elif [ $1 = "debug" ] ; then
	dmesg | tail -30
elif [ $1 = "test" ] ; then
	ip6tables -t mangle --flush
	ip6tables -t mangle -A PREROUTING -j nat64 --ipdst fec0::/64
	iptables -t mangle -A PREROUTING -j nat64 --ipdst 192.168.56.0/24
	ip6tables -t mangle -n -L
	ping6 ::1
elif [ $1 = "setup" ] ; then
	./workflow.sh "ins"
	./workflow.sh "test"
	./workflow.sh "rmv"
	./workflow.sh "ins"
else
	echo "no valid action selected" 
fi
