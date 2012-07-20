#!/bin/bash

# CONFIGURATION:
ipv6_mac="08:00:27:a5:e5:03"    # IPv6 interface's mac address
ipv4_mac="08:00:27:15:ad:cd"	# IPv4 interface's mac address
#
ipv6_int_addr="2001:db8:c0ca:2::1/64"	# IPv6 interface's IP address
ipv6_def_gw="2001:db8:c0ca:2::6"	# IPv6 default gateway
#
ipv4_int_addr="192.168.1.1"	# IPv4 interface's IP address
ipv4_def_gw="192.168.1.4"	# IPv4 default gateway		
#
mod_dir="/home/robertoaceves/nat64/mod"

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
#ipv6_dev="eth1" ; # IPv6 interface
ipv6_dev=`ifconfig -a | grep -i "$ipv6_mac" | sed -e 's/Link.*//'  -e 's/ //g'`
echo "Enabling IPv6 interface"
ifconfig $ipv6_dev up

echo "Remove IPv4 address from $ipv6_dev interface"
ipv4_addr=`ifconfig $ipv6_dev | grep "inet addr" | sed -e 's/.*inet addr://' -e 's/Bcast:.*//' -e 's/ //g'`
ipv4_mask="16"
[ "$ipv4_addr" != "" ] &&
ip addr del $ipv4_addr/$ipv4_mask dev $ipv6_dev

echo "Add IPv6 address: $ipv6_int_addr"
ip -6 addr add $ipv6_int_addr dev $ipv6_dev
#echo "Add IPv6 IPv4-transalted address: $ipv6_int_trans  WARNING!, THIS SHOULD NOT BE USED ANYMORE"
#ifconfig $ipv6_dev inet6 add $ipv6_int_trans_addr
echo "Remove 'fe80' existing IPv6 addresses"
ipv6_fe80=(`ifconfig "$ipv6_dev" | grep 'fe80::' | sed -e 's/.*addr://' -e 's/Scope.*//' -e 's/ //g'`)
[ "${#ipv6_fe80[@]}" -ne "0" ] &&
for addr in "${ipv6_fe80[@]}"; do
	ip -6 addr del $addr dev $ipv6_dev
done
echo "Delete fe80::/64 route"
[ "`ip -6 route | grep fe80`" != ""  ] && ip -6 route del fe80::/64


echo "Detecting IPv4 interface"
ipv4_dev=`ifconfig -a | grep -i "$ipv4_mac" | sed -e 's/Link.*//'  -e 's/ //g'`
echo "Enabling IPv4 interface"
ifconfig $ipv4_dev up

echo "Add ipv4 address: $ipv4_int_addr"
ifconfig $ipv4_dev $ipv4_int_addr up

echo "Remove ipv6 existing addresses"
ipv6_addr=(`ifconfig $ipv4_dev | grep "inet6 addr" | sed -e 's/.*inet6 addr://' -e 's/Scope.*//' -e 's/ //g'`)
[ "${#ipv6_addr[@]}" -ne 0 ] &&
for addr in ${ipv6_addr[@]}; do
	ip -6 addr del $addr dev $ipv4_dev
done

echo "Add default route to IPv4 server, or ISP router in real env."
ip route add default via $ipv4_def_gw dev $ipv4_dev

echo "Add default route to IPv6 client, or IPv6 border router in real env."
ip -6 route add default via $ipv6_def_gw dev $ipv6_dev

exit

pushd "$mod_dir" > /dev/null
echo "Removing NAT64 module"
./workflow.sh "rmv"
echo "Inserting NAT64 module"
./workflow.sh "ins"
echo "Inserting iptables rule's"
./workflow.sh "test"
popd  > /dev/null


echo "Ready"

#gnome-terminal
#tcpdump -e -X -i eth4 "udp port 5000"


