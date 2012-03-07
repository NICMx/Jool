#!/bin/bash

# configuration:
ipv6_mac="08:00:27:a5:e5:03"    # IPv6 interface's mac address
ipv4_mac="08:00:27:15:ad:cd"	# IPv4 interface's mac address
mod_dir="/home/robertoaceves/nat64/myrepo/mod"

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

echo "Add IPv6 address"
ip -6 addr add fec0::1/64 dev $ipv6_dev
echo "Add IPv6 IPv4-transalted address"
#ifconfig $ipv6_dev inet6 add fec0::192.168.56.3/64
ifconfig $ipv6_dev inet6 add fec0::192.168.56.4/64
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

echo "Remove ipv6 existing addresses"
ipv6_addr=(`ifconfig $ipv4_dev | grep "inet6 addr" | sed -e 's/.*inet6 addr://' -e 's/Scope.*//' -e 's/ //g'`)
[ "${#ipv6_addr[@]}" -ne 0 ] &&
for addr in ${ipv6_addr[@]}; do
	ip -6 addr del $addr dev $ipv4_dev
done

echo "Add ipv4 address"
#ip addr add 192.168.56.2/24 broadcast 192.168.56.255 dev $ipv4_dev
ifconfig $ipv4_dev 192.168.56.2 up
echo "Add ipv4 virtual interface"
ifconfig $ipv4_dev:0 192.168.56.114 up


#echo "Disable other interfaces \(internet access\)"
#other_dev=(`ifconfig | grep "HWaddr" | grep -v "$dev"  | sed -e 's/Link.*//'  -e 's/ //g'`)
#[ "${#other_dev[@]}" -ne "0"  ] &&
#for dev in ; do
#	ifconfig $dev down
#done



echo "Inserting NAT64 module"
pushd "$mod_dir" > /dev/null
./workflow.sh "rmv"
./workflow.sh "ins"
./workflow.sh "test"
popd  > /dev/null

echo "Ready"

#gnome-terminal
#tcpdump -e -X -i eth4 "udp port 5000"


