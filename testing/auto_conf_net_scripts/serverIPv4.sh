#!/bin/bash

# configuration: 
ipv4_mac="08:00:27:87:6a:38"    # IPv4 interface's mac address
ipv4_int_addr="192.168.1.4"	# IPv4 interface's IP address
ipv4_def_gw="192.168.1.1"	# IPv4 default gateway

if [ "`whoami`" != "root" ]; then echo "Must be run as superuser"; exit; fi

echo "Removing existing configuration"
dev_list=(`ifconfig -a | grep 'HWaddr' | sed -e 's/Link.*//' -e 's/ //g'`)
[ "${#dev_list[@]}" -ne "0" ] &&
for dev in "${dev_list[@]}"; do
        ifconfig $dev down
        ip    addr flush $dev
        ip -6 addr flush $dev
done

echo "Detecting IPv4 interface"
ipv4_dev=`ifconfig -a | grep -i "$ipv4_mac" | sed -e 's/Link.*//'  -e 's/ //g'`
echo "Enabling IPv4 interface"
ifconfig $ipv4_dev up

echo "Remove existing ipv4 addresses"
ipv4_addr=(`ifconfig $ipv4_dev | grep "inet addr" | sed -e 's/.*inet addr://' -e 's/Bcast:.*//' -e 's/ //g'`)
ipv4_mask="16"
[ "${#ipv4_addr[@]}" -ne 0 ] &&
for addr in ${ipv4_addr[@]}; do
	ip addr del $addr/$ipv4_mask dev $ipv4_dev
done

echo "Add ipv4 address: $ipv4_int_addr"
#ip addr add 192.168.56.4/24 dev $ipv4_dev
ifconfig $ipv4_dev $ipv4_int_addr up
echo "Add default route"
ip route add default via $ipv4_def_gw


echo "Remove ipv6 existing addresses"
ipv6_addr=(`ifconfig $ipv4_dev | grep "inet6 addr" | sed -e 's/.*inet6 addr://' -e 's/Scope.*//' -e 's/ //g'`)
[ "${#ipv6_addr[@]}" -ne 0 ] &&
for addr in ${ipv6_addr[@]}; do
        ip -6 addr del $addr dev $ipv4_dev
done 

#echo "Disable other interfaces \(internet access\)"
#other_dev=(`ifconfig | grep "HWaddr" | grep -v "$dev"  | sed -e 's/Link.*//'  -e 's/ //g'`)
#[ "${#other_dev[@]}" -ne "0"  ] &&
#for dev in ; do
#        ifconfig $dev down
#done


#echo "ADD IPv6 ADDRESS TO THIS IPv4 MACHINE"
#ip -6 addr add fec0::3/64 dev $ipv4_dev
#echo "Delete fe80::/64 route"
#ip -6 route del fe80::/64
#echo "Add default IPv6 route"
#ip -6 route add default via fec0::1

echo "Ready"

#gnome-terminal
#tcpdump -e -X -i eth1 "udp port 5000"

