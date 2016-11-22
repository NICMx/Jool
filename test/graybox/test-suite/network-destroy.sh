#!/bin/bash

# Reverts the stuff network-create.sh did.
#
# Arguments:
# $1: Either "siit" or "nat64", depending on which tests you ran.
#     (No quotes.)

. config

echo "Destroying the $1 network..."
ip netns exec $NS xlat/end.sh $XLAT_V6_INTERFACE $XLAT_V4_INTERFACE
client/$1/end.sh $CLIENT_V6_INTERFACE $CLIENT_V4_INTERFACE
