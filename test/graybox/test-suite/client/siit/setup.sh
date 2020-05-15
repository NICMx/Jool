#!/bin/bash

# Parameters:
# $1: Interface where the IPv6 traffic will be seen.
# $2: Interface where the IPv4 traffic will be seen.

ip addr flush dev $1 scope global
ip addr flush dev $2 scope global
ip link set $1 up
ip link set $2 up

# H6's config
ip addr add 2001:db8:1c0:2:21::/64 dev $1
ip -6 route add 2001:db8:1c6:3364::/40 via 2001:db8:1c0:2:1::

# H4's config
ip addr add 198.51.100.2/24 dev $2
ip route add 192.0.2.0/24 via 198.51.100.1

insmod `dirname $0`/../../../mod/graybox.ko
