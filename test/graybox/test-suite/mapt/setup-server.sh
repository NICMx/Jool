#!/bin/bash

set -x

LINK_OP=$1
ENTRY_OP=$2

ip link set lo up

ip addr $ENTRY_OP 203.0.113.8/24 dev server2br
ip link set server2br $LINK_OP

ip route $ENTRY_OP 192.0.2.0/24 via 203.0.113.1

