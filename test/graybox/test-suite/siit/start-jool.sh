#!/bin/sh

# To compile, simply run `make`. No need for configure.
# You need your kernel headers & Kbuild & stuff.

set -x

sudo insmod /home/al/git/joolif/mod/joolif.ko

sudo sysctl -w net.ipv4.conf.all.forwarding=1 > /dev/null
sudo sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

sudo ip addr flush dev siit0 scope global
sudo ip link set siit0 up
sudo ip addr add 2001:db8:1c0:2:21::/40 dev siit0 # 192.0.2.33
sudo ip addr add 198.51.100.2/5 dev siit0 # 2001:db8:1c6:3364:2::

sudo usr/joolif siit0 pool6 2001:db8:100::/40
sudo usr/joolif siit0 pool6791v4 198.51.100.1
sudo usr/joolif siit0 pool6791v6 2001:db8:1c0:2:1::

# Not sure if this is still relevant
sudo sysctl -w net.ipv6.auto_flowlabels=0 > /dev/null

# Only one interface can exist at a time, for now.
#
# Sample pings to yourself through xlator:
#	ping 2001:db8:1c6:3364:2::
#	ping 192.0.2.33
#
# End:
#	sudo rmmod joolif

