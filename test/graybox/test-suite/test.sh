#!/bin/bash

# Arguments:
# $1: Either "siit" or "nat64", depending on which tests you want to run.
#     (No quotes.)
# $2: Parameter to client/$1/send.sh.
#
# Requires ./setup.sh to have been called.

. config

# (Configure client and translator, each in its own box.)
echo "Preparing..."
ip netns exec $NS xlat/$1.sh $XLAT_V6_INTERFACE $XLAT_V4_INTERFACE
client/$1/setup.sh $CLIENT_V6_INTERFACE $CLIENT_V4_INTERFACE

#sleep 6

echo "Testing $1..."
client/$1/send.sh $2
result=$?

echo "Cleaning up..."
ip netns exec $NS xlat/end.sh $XLAT_V6_INTERFACE $XLAT_V4_INTERFACE
client/$1/end.sh $CLIENT_V6_INTERFACE $CLIENT_V4_INTERFACE

exit $result
