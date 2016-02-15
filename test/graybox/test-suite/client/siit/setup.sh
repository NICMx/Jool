#!/bin/bash
ITF0=eth0
ITF1=eth1

sudo service network-manager stop

sudo ip addr flush dev $ITF0 scope global
sudo ip addr flush dev $ITF1 scope global

sudo ip link set $ITF0 up
sudo ip link set $ITF1 up

# H4's config (http://tools.ietf.org/html/rfc6145#appendix-A)
sudo ip addr add 198.51.100.2/24 dev $ITF0
sudo ip route add 192.0.2.0/24 via 198.51.100.1

# H6's config
sudo ip addr add 2001:db8:1c0:2:21::/64 dev $ITF1
sudo ip route add default via 2001:db8:1c0:2:1::

sudo modprobe graybox

