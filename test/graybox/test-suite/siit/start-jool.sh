#!/bin/sh

sudo insmod /home/al/git/jool/test/graybox/mod/graybox.ko
sudo insmod /home/al/git/joolif/joolif.ko

sudo sysctl -w net.ipv4.conf.all.forwarding=1 > /dev/null
sudo sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

sudo ip addr flush dev siit0 scope global
sudo ip link set siit0 up
sudo ip addr add 2001:db8:1c0:2:21::/40 dev siit0
sudo ip addr add 198.51.100.2/5 dev siit0

# Relevant whenever the kernel responds an ICMPv6 error on behalf of Jool.
sudo sysctl -w net.ipv6.auto_flowlabels=0 > /dev/null
