#!/bin/bash

# Parameters:
# $1: Interface where the IPv6 traffic will be seen.
# $2: Interface where the IPv4 traffic will be seen.

ip addr flush dev $1 scope global
ip addr flush dev $2 scope global
ip link set $1 up
ip link set $2 up

# H6's config
ip addr add 2001:db8::5/96 dev $1
ip -6 route add 64:ff9b::/96 via 2001:db8::1

# H4's config
ip addr add 192.0.2.5/24 dev $2
sysctl -w net.ipv4.conf.all.forwarding=1 > /dev/null

insmod `dirname $0`/../../../mod/graybox.ko
