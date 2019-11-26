#!/bin/bash

modprobe -rq jool_siit
modprobe -rq jool
ip addr flush dev $1 scope global
ip addr flush dev $2 scope global
ip link set $1 up
ip link set $2 up

ip addr add 2001:db8::1/96 dev $1
ip addr add 192.0.2.2/24 dev $2
ip route add 203.0.113.0/24 via 192.0.2.5

sysctl -w net.ipv4.conf.all.forwarding=1     > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=1     > /dev/null
modprobe jool
jool instance add -6 64:ff9b::/96 --iptables
jool pool4 add 192.0.2.2 1-3000 --tcp
jool pool4 add 192.0.2.2 1-3000 --udp
jool pool4 add 192.0.2.2 1-3000 --icmp
jool bib add 192.0.2.2#2000 2001:db8::5#2000 --tcp
jool bib add 192.0.2.2#2000 2001:db8::5#2000 --udp
jool bib add 192.0.2.2#1    2001:db8::5#1    --icmp

ip6tables -t mangle -A PREROUTING -d 64:ff9b::/96                       -j JOOL
iptables  -t mangle -A PREROUTING -d 192.0.2.2    -p tcp --dport 1:3000 -j JOOL
iptables  -t mangle -A PREROUTING -d 192.0.2.2    -p udp --dport 1:3000 -j JOOL
iptables  -t mangle -A PREROUTING -d 192.0.2.2    -p icmp               -j JOOL

# Relevant whenever the kernel responds an ICMPv6 error on behalf of Jool.
sysctl -w net.ipv6.auto_flowlabels=0 > /dev/null

# ptb64 test
jool bib add 192.0.2.2#1000 2001:db8:1::5#1001 --udp

# ptb66 test
#ip route add 2001:db8:1::/96 via 2001:db8::5
#jool bib add 192.0.2.2#1002 2001:db8::5#1003   --udp
