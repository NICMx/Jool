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

sudo ip addr add 198.51.100.1/24 dev $ITF0
sudo ip addr add 2001:db8:1c0:2:1::/64 dev $ITF1

sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# FIXME agregar o no agregar la direccion de IPv4 a mi interfaz de IPv6 ó asignar la ruta por esta interfaz
#sudo ip addr add 192.0.2.1/24 dev $ITF1
#sudo ip route add 192.0.2.0/24 dev $ITF1
# FIXME como este es el router de "salida a internet" tiene una ruta default por la interfaz de IPv4
#sudo ip route add default via 198.51.100.2

sudo dmesg -C

sudo modprobe jool_siit pool6=2001:db8:100::/40

# pool6791 test
sudo jool_siit -ea 2001:db8:3::/120 1.0.0.0/24
sudo jool_siit -ea 2001:db8:2::/120 10.0.0.0/24
sudo jool_siit --pool6791 --add 203.0.113.8
sudo ip route add 2001:db8:3::/120 via 2001:db8:1c0:2:21::

dmesg