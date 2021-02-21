#!/bin/sh

set -x

LINK_OP=$1
ENTRY_OP=$2
FORWARDING_OP=$3
JOOL_OP=$4

ip link set lo up

ip addr $ENTRY_OP 2001:db8::b/24 dev br2ce
ip link set br2ce $LINK_OP

ip addr $ENTRY_OP 203.0.113.1/24 dev br2server
ip link set br2server $LINK_OP

ip route $ENTRY_OP 2001:db8:4464:8::/64 via 2001:db8::ce

sysctl -w net.ipv4.conf.all.forwarding=$FORWARDING_OP > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=$FORWARDING_OP > /dev/null

# ------------------------------------------

case "$JOOL_OP" in
	start)
		modprobe jool_mapt
		jool_mapt instance add "BR" --iptables --dmr 64:ff9b::/96
		jool_mapt -i "BR" fmr add 2001:db8:4464::/56 192.0.2.0/24 8
		#jool_mapt -i "BR" global update logging-debug true

		iptables  -t mangle -A PREROUTING -d 192.0.2.0/24 -j JOOL_MAPT --instance "BR"
		ip6tables -t mangle -A PREROUTING -d 64:ff9b::/96 -j JOOL_MAPT --instance "BR"
		;;
	stop)
		iptables  -t mangle -D PREROUTING -d 192.0.2.0/24 -j JOOL_MAPT --instance "BR"
		ip6tables -t mangle -D PREROUTING -d 64:ff9b::/96 -j JOOL_MAPT --instance "BR"
		modprobe -r jool_mapt
		;;
esac

