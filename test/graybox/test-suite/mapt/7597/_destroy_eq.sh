#!/bin/sh

ip netns exec ce11n ip6tables -t mangle -F PREROUTING
ip netns exec ce11n iptables  -t mangle -F PREROUTING
ip netns exec ce12n ip6tables -t mangle -F PREROUTING
ip netns exec ce12n iptables  -t mangle -F PREROUTING
ip netns exec ce21n ip6tables -t mangle -F PREROUTING
ip netns exec ce21n iptables  -t mangle -F PREROUTING
ip netns exec ce11t ip6tables -t mangle -F PREROUTING
ip netns exec ce11t iptables  -t mangle -F PREROUTING
ip netns exec ce12t ip6tables -t mangle -F PREROUTING
ip netns exec ce12t iptables  -t mangle -F PREROUTING
ip netns exec ce21t ip6tables -t mangle -F PREROUTING
ip netns exec ce21t iptables  -t mangle -F PREROUTING
ip netns exec br    ip6tables -t mangle -F PREROUTING
ip netns exec br    iptables  -t mangle -F PREROUTING

modprobe -r jool_mapt
rmmod graybox

ip netns del c111
ip netns del c112
ip netns del c121
ip netns del c211
ip netns del ce11n
ip netns del ce12n
ip netns del ce21n
ip netns del ce11t
ip netns del ce12t
ip netns del ce21t
ip netns del br
ip netns del r4

ip link set br0 down
brctl delbr br0
ip link set br1 down
brctl delbr br1

