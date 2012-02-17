#! /bin/bash

ifconfig eth1 add fec0:24::c0a8:0180/64
ip -6 addr del fe80::204:e2ff:fe25:6ab4/64 dev eth0
ip -6 addr del fe80::221:70ff:fe06:2916/64 dev eth1
ip route del fe80::/64
ifconfig eth0:0 192.168.1.11 up

