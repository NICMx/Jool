#!/bin/bash

modprobe -r jool_siit
modprobe -r jool
ip addr flush dev $1 scope global
ip addr flush dev $2 scope global
ip link set $1 up
ip link set $2 up

ip addr add 2001:db8:1c0:2:1::/64 dev $1
ip addr add 198.51.100.1/24 dev $2

sysctl -w net.ipv4.conf.all.forwarding=1 > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
modprobe jool_siit pool6=2001:db8:100::/40

# pool6791 test
jool_siit -ea 2001:db8:3::/120 1.0.0.0/24
jool_siit -ea 2001:db8:2::/120 10.0.0.0/24
jool_siit --pool6791 --add 203.0.113.8
ip route add 2001:db8:3::/120 via 2001:db8:1c0:2:21::
