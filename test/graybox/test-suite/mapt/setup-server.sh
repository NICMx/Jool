#!/bin/bash

LINK_OP=$1
ENTRY_OP=$2

ip link set server2br $LINK_OP
ip addr $ENTRY_OP 203.0.113.8/24 dev server2br
ip route $ENTRY_OP 192.0.2.0/24 via 203.0.113.1

