#!/bin/bash

# Configures the network in which a particular translator's tests will be run.
#
# Arguments:
# $1: Either "siit" or "nat64", depending on which tests you want to run.
#     (Defaults to "siit".)
#
# Though this script tends to succeed immediately, whether the kernel has
# finished setting up the network is another matter.
# You might need to wait about ~5 seconds before you can send packets through
# this network.

. config

NETWORK=siit
if [ -n "${1+set}" ]; then
	NETWORK=$1
fi

echo "Preparing the $NETWORK network..."
ip netns exec $NS xlat/$NETWORK.sh $XLAT_V6_INTERFACE $XLAT_V4_INTERFACE
client/$NETWORK/setup.sh $CLIENT_V6_INTERFACE $CLIENT_V4_INTERFACE
