#!/bin/bash
#Run this if you want to set the same machine as both client and translator
#After running this, there is no need to run the client/siit/setup.sh script.

# We are only going to use virtual interfaces, however it is strongly recommended
# to flush and bring down any other interface to eliminate any noise that may affect
# the tests
INTERFACES=(eth0 eth1)
# Add any other physical interface you want to shut down here... e.g. INTERFACES+=eth2

sudo service network-manager stop
sudo modprobe -r jool_siit
sudo modprobe -r jool
sudo ip netns del blue

# We bring down any interface we set up before
for i in ${INTERFACES[@]}; do
	# Just to make sure itf's are down...
	sudo ip link set $i down
	sudo ip addr flush dev $i scope global
done

sudo ip netns add blue
sudo ip link add wire0 type veth peer name wire1
sudo ip link set wire1 netns blue

# Global netns side of the tunnel
sudo ip link set wire0 up
# H4's config (http://tools.ietf.org/html/rfc6145#appendix-A)
sudo ip addr add 198.51.100.2/24 dev wire0
sudo ip addr add 2001:db8:1c0:2:21::/64 dev wire0

# 'blue' netns side of the tunnel
sudo ip netns exec blue ip link set wire1 up
sudo ip netns exec blue ip addr add 198.51.100.1/24 dev wire1
sudo ip netns exec blue ip addr add 2001:db8:1c0:2:1::/64 dev wire1

sudo ip route add 192.0.2.0/24 via 198.51.100.1
sudo ip route add default via 2001:db8:1c0:2:1::

sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# FIXME agregar o no agregar la direccion de IPv4 a mi interfaz de IPv6 ó asignar la ruta por esta interfaz
#sudo ip addr add 192.0.2.1/24 dev $ITF1
#sudo ip route add 192.0.2.0/24 dev $ITF1
# FIXME como este es el router de "salida a internet" tiene una ruta default por la interfaz de IPv4
#sudo ip route add default via 198.51.100.2

sudo dmesg -C

sudo ip netns exec blue modprobe jool_siit pool6=2001:db8:100::/40

# pool6791 test
sudo ip netns exec blue jool_siit -ea 2001:db8:3::/120 1.0.0.0/24
sudo ip netns exec blue jool_siit -ea 2001:db8:2::/120 10.0.0.0/24
sudo ip netns exec blue jool_siit --pool6791 --add 203.0.113.8
sudo ip netns exec blue ip route add 2001:db8:3::/120 via 2001:db8:1c0:2:21::

sudo modprobe graybox

dmesg