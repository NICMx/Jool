#!/bin/bash

config_file="../etc/nat64_configuration/nat64.conf"
if [ -f "$config_file" ]; then
	pool_net=`awk '/ipv4_addr_net[ =]/{printf "%s/",$3} /ipv4_addr_net_mask_bits/{printf "%d\n",$3}' "$config_file"`
	pref64=`awk '/ipv6_net_prefix/{printf "%s/",$3} /ipv6_net_mask_bits/{printf "%d\n",$3}' "$config_file"`
else
	echo "NAT64. WARNING. Configuration file NOT found. Using default values"
	header_file="../include/xt_nat64_module_conf.h"
	pool_net=` awk '/IPV4_DEF_NET/{gsub(/[\"]/,"",$3); printf "%s/",$3} /IPV4_DEF_MASKBITS/{printf "%d\n",$3}'  "$header_file"`
	pref64=` awk '/IPV6_DEF_PREFIX/{gsub(/[\"]/,"",$3); printf "%s/",$3} /IPV6_DEF_MASKBITS/{printf "%d\n",$3}'  "$header_file"`
fi

if [ $1 = "ins" ] ; then
	sudo modprobe ipv6
	sudo modprobe ip_tables
	sudo modprobe nf_conntrack
	sudo modprobe nf_conntrack_ipv4
	sudo ip6tables -t mangle --flush
	sudo insmod nat64.ko

	# Enable ipv6 and ipv4 forwarding
	sudo sysctl -w net.ipv4.conf.all.forwarding=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1

	echo "installed the NAT64 module"
elif [ $1 = "up" ] ; then
	sudo ./workflow.sh "rmv"
	sudo ./workflow.sh "ins"
	sudo ./workflow.sh "test"
elif [ $1 = "rmv" ] ; then
	sudo ip6tables -t mangle --flush
	sudo iptables -t mangle --flush
	sudo rmmod nat64.ko
	echo "removed the NAT64 module"
elif [ $1 = "debug" ] ; then
	sudo dmesg | tail -30
elif [ $1 = "test" ] ; then
	echo "Flusing IPv4 & IPv6 mangle iptables"
	sudo iptables -t mangle --flush
	sudo ip6tables -t mangle --flush
	#echo "Adding ip6tables rule to drop packets originating \"Hairpining loops\"."
	#sudo ip6tables -t mangle -A PREROUTING -s 64:ff9b::/96 -j DROP
	echo "Adding ip6table rule to catch NAT64 packets (having the defined IPv6 prefix)"
	#sudo ip6tables -t mangle -A PREROUTING -j nat64 --ipdst 64:ff9b::/96
	sudo ip6tables -t mangle -A PREROUTING -j nat64 --ipdst "$pref64" # Better use the value in config file. Rob.
	echo "Adding iptable rule to catch NAT64 packets (destined to the pool network)"
	#sudo iptables -t mangle -A PREROUTING -j nat64 --ipdst 192.168.2.0/24
	sudo iptables -t mangle -A PREROUTING -j nat64 --ipdst "$pool_net" # Better use the value in config file. Rob.
	echo "Showing actual content of mangle table for IPv4 & IPv6"
	sudo iptables -t mangle -n -L
	sudo ip6tables -t mangle -n -L
elif [ $1 = "setup" ] ; then
	sudo ./workflow.sh "ins"
	sudo ./workflow.sh "test"
	sudo ./workflow.sh "rmv"
	sudo ./workflow.sh "ins"
else
	echo "no valid action selected" 
fi
