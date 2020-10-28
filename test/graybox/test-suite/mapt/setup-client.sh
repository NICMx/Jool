#!/bin/sh

LINK_OP=$1
ENTRY_OP=$2

ip link set client2ce $LINK_OP
ip addr $ENTRY_OP 192.168.0.8/24 dev client2ce
ip route $ENTRY_OP default via 192.168.0.1

