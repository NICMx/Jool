#!/bin/sh

LINK_OP=$1
ENTRY_OP=$2
FORWARDING_OP=$3
JOOL_OP=$4

ip link set ce2client $LINK_OP
ip addr $ENTRY_OP 192.168.0.1/24 dev ce2client

ip link set ce2br $LINK_OP
ip addr $ENTRY_OP 2001:db8::ce/96 dev ce2br

ip route $ENTRY_OP 64:ff9b::/96 via 2001:db8::b

sysctl -w net.ipv4.conf.all.forwarding=$FORWARDING_OP > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=$FORWARDING_OP > /dev/null

# ------------------------------------------

case "$JOOL_OP" in
	start)
		modprobe jool_mapt
		jool_mapt instance add "CE" --netfilter \
			--end-user-ipv6-prefix 2001:db8:4464:1::/64 \
			--bmr.ipv6-prefix 2001:db8:4464::/56 \
			--bmr.ipv4-prefix 192.0.2.0/24 \
			--bmr.ea-bits-length 8 \
			--dmr 64:ff9b::/96
		;;
	stop)
		modprobe -r jool_mapt
		;;
esac

