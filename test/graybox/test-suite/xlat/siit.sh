#!/bin/bash

modprobe -rq jool_siit
modprobe -rq jool
ip addr flush dev $1 scope global
ip addr flush dev $2 scope global
ip link set $1 up
ip link set $2 up

ip addr add 2001:db8:1c0:2:1::/64 dev $1
ip addr add 198.51.100.1/24 dev $2

sysctl -w net.ipv4.conf.all.forwarding=1 > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
modprobe jool_siit
jool_siit instance add --iptables -6 2001:db8:100::/40

ip6tables -t mangle -A PREROUTING -d 2001:db8:1c6:3364:2:: -j JOOL_SIIT
iptables  -t mangle -A PREROUTING -d 192.0.2.33            -j JOOL_SIIT

# pool6791 test
jool_siit eamt add 2001:db8:3::/120 1.0.0.0/24
jool_siit eamt add 2001:db8:2::/120 10.0.0.0/24
jool_siit global update rfc6791v4-prefix 203.0.113.8
ip route add 2001:db8:3::/120 via 2001:db8:1c0:2:21::
