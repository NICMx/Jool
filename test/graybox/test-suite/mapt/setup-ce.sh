#!/bin/sh

set -x

LINK_OP=$1
ENTRY_OP=$2
FORWARDING_OP=$3
JOOL_OP=$4

ip link set lo up

ip addr $ENTRY_OP 192.0.2.1/24 dev ce2client
ip link set ce2client $LINK_OP

ip addr $ENTRY_OP 2001:db8::ce/96 dev ce2br
ip link set ce2br $LINK_OP

ip route $ENTRY_OP 64:ff9b::/96 via 2001:db8::b

sysctl -w net.ipv4.conf.all.forwarding=$FORWARDING_OP > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=$FORWARDING_OP > /dev/null

# ------------------------------------------

case "$JOOL_OP" in
	start)
		modprobe jool_mapt
		jool_mapt instance add "CE" --iptables --dmr 64:ff9b::/96
		jool_mapt -i "CE" global update end-user-ipv6-prefix 2001:db8:4464:8::/64
		jool_mapt -i "CE" global update bmr 2001:db8:4464::/56 192.0.2.0/24 8
		jool_mapt -i "CE" global update map-t-type CE

		#jool_mapt -i "CE" global update logging-debug true

		iptables  -t mangle -A PREROUTING -d 203.0.113.0/24       -j JOOL_MAPT --instance "CE"
		ip6tables -t mangle -A PREROUTING -d 2001:db8:4464:8::/64 -j JOOL_MAPT --instance "CE"
		;;
	stop)
		iptables  -t mangle -D PREROUTING -d 203.0.113.0/24       -j JOOL_MAPT --instance "CE"
		ip6tables -t mangle -D PREROUTING -d 2001:db8:4464:8::/64 -j JOOL_MAPT --instance "CE"
		modprobe -r jool_mapt
		;;
esac

