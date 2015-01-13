#!/bin/bash

INTERFACES=( $(ifconfig -a | grep -e '^[a-z]' | cut -d':' -f1) )

LIST=("rx" "tx" "sg" "tso" "ufo" "gso" "gro" "lro" "rxvlan" "txvlan" "ntuple" "rxhash")

for interface in ${INTERFACES[@]}
do
		for elem in ${LIST[@]}
		do
			sudo ethtool --offload $interface $elem off
		done
done
