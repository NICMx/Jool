#!/bin/sh

sudo ip netns exec ce11 ip6tables -t mangle -F PREROUTING
sudo ip netns exec ce11 iptables  -t mangle -F PREROUTING
sudo ip netns exec ce12 ip6tables -t mangle -F PREROUTING
sudo ip netns exec ce12 iptables  -t mangle -F PREROUTING
sudo ip netns exec ce21 ip6tables -t mangle -F PREROUTING
sudo ip netns exec ce21 iptables  -t mangle -F PREROUTING
sudo ip netns exec br   ip6tables -t mangle -F PREROUTING
sudo ip netns exec br   iptables  -t mangle -F PREROUTING

sudo modprobe -r jool_mapt
sudo rmmod graybox

sudo ip netns del c111
sudo ip netns del c112
sudo ip netns del c121
sudo ip netns del c211
sudo ip netns del ce11
sudo ip netns del ce12
sudo ip netns del ce21
sudo ip netns del br
sudo ip netns del r4

sudo ip link set br0 down
sudo brctl delbr br0
sudo ip link set br1 down
sudo brctl delbr br1
