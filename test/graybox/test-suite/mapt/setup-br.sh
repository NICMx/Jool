#!/bin/sh

LINK_OP=$1
ENTRY_OP=$2
FORWARDING_OP=$3
JOOL_OP=$4

ip link set br2ce $LINK_OP
ip addr $ENTRY_OP 2001:db8::d/24 dev br2ce

ip link set br2server $LINK_OP
ip addr $ENTRY_OP 203.0.113.1/24 dev br2server

ip route $ENTRY_OP 2001:db8:4464:1::/64 via 2001:db8::ce

sysctl -w net.ipv4.conf.all.forwarding=$FORWARDING_OP > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=$FORWARDING_OP > /dev/null

# ------------------------------------------

case "$JOOL_OP" in
	start)
		modprobe jool_mapt
		jool_mapt instance add "BR" --netfilter --dmr 64:ff9b::/96
		jool_mapt -i "BR" fmr add 2001:db8:4464::/56 192.0.2.0/24 8
		;;
	stop)
		modprobe -r jool_mapt
		;;
esac

