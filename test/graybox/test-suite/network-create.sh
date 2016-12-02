#!/bin/bash

# Configures the network in which a particular translator's tests will be run.
#
# Arguments:
# $1: Either "siit" or "nat64", depending on which tests you want to run.
#     (No quotes.)
#
# Though this script tends to succeed immediately, whether the kernel has
# finished setting up the network is another matter.
# You might need to wait about ~5 seconds before you can send packets through
# this network.

. config

echo "Preparing the $1 network..."
ip netns exec $NS xlat/$1.sh $XLAT_V6_INTERFACE $XLAT_V4_INTERFACE
client/$1/setup.sh $CLIENT_V6_INTERFACE $CLIENT_V4_INTERFACE
