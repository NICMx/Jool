#! /bin/bash 

# NAT64
ifconfig eth0 up
ip -6 addr del fe80::a00:27ff:febd:475b/64 dev eth0
ifconfig eth0 inet6 add fec0::1/64
ip route del fe80::/64
