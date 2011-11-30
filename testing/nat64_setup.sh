#! /bin/bash 

# NAT64
sudo ifconfig eth0:0 192.168.56.114 up
ifconfig eth0 up
ip -6 addr del fe80::a00:27ff:febd:475b/64 dev eth0
ifconfig eth0 inet6 add fec0::1/64
ip route del fe80::/64
sudo ifconfig eth0 inet6 add fec0::c0a8:3802/64

