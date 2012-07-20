#!/bin/bash

# CONFIGURATION:
ipv6_mac="08:00:27:35:54:5d"    	# IPv6 interface's mac address
ipv6_int_addr="2001:db8:c0ca:2::6/64"	# IPv6 interface's IP address
ipv6_def_gw="2001:db8:c0ca:2::1"	# IPv6 default gateway
#

if [ "`whoami`" != "root" ]; then echo "Must be run as superuser"; exit; fi

echo "Removing existing configuration"
dev_list=(`ifconfig -a | grep 'HWaddr' | sed -e 's/Link.*//' -e 's/ //g'`)
[ "${#dev_list[@]}" -ne "0" ] &&
for dev in "${dev_list[@]}"; do
	ifconfig $dev down
	ip    addr flush $dev
	ip -6 addr flush $dev
done

echo "Detecting IPv6 interface"
#dev="eth1" ; # IPv6 interface
ipv6_dev=`ifconfig -a | grep -i "$ipv6_mac" | sed -e 's/Link.*//'  -e 's/ //g'` 
echo "Enabling IPv6 interface"
ifconfig $ipv6_dev up

#echo "Disable other interfaces \(internet access\)"
#other_dev=(`ifconfig | grep "HWaddr" | grep -v "$dev"  | sed -e 's/Link.*//'  -e 's/ //g'`)
#[ "${#other_dev[@]}" -ne "0"  ] &&
#for dev in ; do
#	ifconfig $dev down
#done

echo "Remove ipv4 addresses"
ipv4_addr=`ifconfig $ipv6_dev | grep "inet addr" | sed -e 's/.*inet addr://' -e 's/Bcast:.*//' -e 's/ //g'`
ipv4_mask="16"
[ "$ipv4_addr" != "" ] &&
ip addr del $ipv4_addr/$ipv4_mask dev $ipv6_dev

echo "Remove ipv6 existing addresses"
ipv6_addr=(`ifconfig $ipv6_dev | grep "inet6 addr" | sed -e 's/.*inet6 addr://' -e 's/Scope.*//' -e 's/ //g'`)
[ "${#ipv6_addr[@]}" -ne "0" ] &&
for addr in ${ipv6_addr[@]}; do
	ip -6 addr del $addr dev $ipv6_dev
done

echo "Add ipv6 address: $ipv6_int_addr"
ip -6 addr add $ipv6_int_addr dev $ipv6_dev
echo "Add default route: $ipv6_def_gw"
ip -6 route add default via $ipv6_def_gw
echo "Delete fe80::/64 route"
[ "`ip -6 route | grep fe80`" != ""  ] && ip -6 route del fe80::/64

echo "Ready"

#gnome-terminal
#tcpdump -e -X -i eth1 "udp port 5000"

