#!/bin/bash
ITF0=eth0
ITF1=eth1

sudo service network-manager stop

sudo ip addr flush dev $ITF0 scope global
sudo ip addr flush dev $ITF1 scope global

sudo ip link set $ITF0 up
sudo ip link set $ITF1 up

sudo ip addr add 192.0.2.5/24 dev $ITF0
sudo ip addr add 2001:db8::5/96 dev $ITF1

sudo ip -6 route add 64:ff9b::/96 via 2001:db8::1

sudo modprobe graybox
