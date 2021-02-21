#!/bin/sh

ip netns exec ce11 ip6tables -t mangle -F PREROUTING
ip netns exec ce11 iptables  -t mangle -F PREROUTING
ip netns exec ce12 ip6tables -t mangle -F PREROUTING
ip netns exec ce12 iptables  -t mangle -F PREROUTING
ip netns exec ce21 ip6tables -t mangle -F PREROUTING
ip netns exec ce21 iptables  -t mangle -F PREROUTING
ip netns exec br   ip6tables -t mangle -F PREROUTING
ip netns exec br   iptables  -t mangle -F PREROUTING

modprobe -r jool_mapt
rmmod graybox

ip netns del c111
ip netns del c112
ip netns del c121
ip netns del c211
ip netns del ce11
ip netns del ce12
ip netns del ce21
ip netns del br
ip netns del r4

ip link set br0 down
brctl delbr br0
ip link set br1 down
brctl delbr br1

