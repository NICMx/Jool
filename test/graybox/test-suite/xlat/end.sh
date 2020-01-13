#!/bin/bash

ip6tables -t mangle -F
iptables  -t mangle -F
#/home/al/git/nftables/src/nft delete chain inet graybox test
#/home/al/git/nftables/src/nft delete table inet graybox

modprobe -rq jool_siit
modprobe -rq jool
