#!/bin/sh




set -x

IFNAME="siit0"

sudo insmod /home/al/git/jool/test/graybox/mod/graybox.ko
sudo insmod /home/al/git/joolif/mod/joolif.ko

sudo sysctl -w net.ipv4.conf.all.forwarding=1 > /dev/null
sudo sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

sudo ip link add name $IFNAME type siit
sudo ip addr add 2001:db8:1c0:2:21::/40 dev $IFNAME # 192.0.2.33
sudo ip addr add 198.51.100.2/5 dev $IFNAME # 2001:db8:1c6:3364:2::
sudo ip link set $IFNAME up

#sudo /home/al/git/joolif/usr/joolif $IFNAME pool6 2001:db8:100::/40
#sudo /home/al/git/joolif/usr/joolif $IFNAME pool6791v4 198.51.100.1
#sudo /home/al/git/joolif/usr/joolif $IFNAME pool6791v6 2001:db8:1c0:2:1::

# Not sure if this is still relevant
sudo sysctl -w net.ipv6.auto_flowlabels=0 > /dev/null

# Sample pings to yourself through xlator:
#	ping 2001:db8:1c6:3364:2::
#	ping 192.0.2.33
#
# End:
#	sudo ip link del siit0
#	sudo rmmod joolif

