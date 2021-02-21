#!/bin/sh

set -x

LINK_OP=$1
ENTRY_OP=$2

ip link set lo up

ip addr $ENTRY_OP 192.0.2.8/24 dev client2ce
ip link set client2ce $LINK_OP

ip route $ENTRY_OP default via 192.0.2.1

