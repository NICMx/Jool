#!/bin/bash
ITF0=eth0
ITF1=eth1

sudo service network-manager stop
sudo modprobe -r jool_siit
sudo modprobe -r jool

sudo ip addr flush dev $ITF0 scope global
sudo ip addr flush dev $ITF1 scope global

sudo ip link set $ITF0 up
sudo ip link set $ITF1 up

#sudo ip addr add 192.0.2.1/24 dev $ITF0
sudo ip addr add 192.0.2.2/24 dev $ITF0
sudo ip addr add 2001:db8::1/96 dev $ITF1

sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

sudo dmesg -C

sudo modprobe jool pool6=64:ff9b::/96
sudo jool -4a 192.0.2.2 1-3000
sudo jool -batu 192.0.2.2#2000 2001:db8::5#2000
sudo jool -bai 192.0.2.2#1 2001:db8::5#1

# PTB test
sudo ip route add 2001:db8:1::/96 via 2001:db8::5
# ?
# sudo ip route add 203.0.113.0/24 via 192.0.2.5
sudo jool -batu 192.0.2.2#1000 2001:db8:1::5#1001
sudo jool -batu 192.0.2.2#1002 2001:db8::6#1003
sudo jool --source-icmpv6-errors-better true

dmesg

