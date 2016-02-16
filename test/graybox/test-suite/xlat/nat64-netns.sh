#!/bin/bash
#Run this if you want to set the same machine as both client and translator
#After running this, there is no need to run the client/nat64/setup.sh script.

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
sudo ip addr add 192.0.2.5/24 dev wire0
sudo ip addr add 2001:db8::5/96 dev wire0

# 'blue' netns side of the tunnel
sudo ip netns exec blue ip link set wire1 up
sudo ip netns exec blue ip addr add 192.0.2.2/24 dev wire1
sudo ip netns exec blue ip addr add 2001:db8::1/96 dev wire1

#sudo ip addr add 192.0.2.1/24 dev $ITF0

sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

sudo ip -6 route add 64:ff9b::/96 via 2001:db8::1

sudo dmesg -C

sudo ip netns exec blue modprobe jool pool6=64:ff9b::/96
sudo ip netns exec blue jool -4a 192.0.2.2 1-3000
sudo ip netns exec blue jool -batu 192.0.2.2#2000 2001:db8::5#2000
sudo ip netns exec blue jool -bai 192.0.2.2#1 2001:db8::5#1

# PTB test
sudo ip netns exec blue ip route add 2001:db8:1::/96 via 2001:db8::5
# ?
# sudo ip route add 203.0.113.0/24 via 192.0.2.5
sudo ip netns exec blue jool -batu 192.0.2.2#1000 2001:db8:1::5#1001
sudo ip netns exec blue jool -batu 192.0.2.2#1002 2001:db8::6#1003
sudo ip netns exec blue jool --source-icmpv6-errors-better true

sudo modprobe graybox

dmesg

