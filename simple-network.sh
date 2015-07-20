sudo service network-manager stop

sudo ip link set eth0 up
sudo ip addr add 1::1/96 dev eth0

sudo ip link set eth1 up
sudo ip addr add 192.0.2.1/24 dev eth1

