#!/bin/bash

# Reverts the stuff namespace-create.sh did.

. config

echo "Destroying the $NS namespace..."
ip link del $CLIENT_V6_INTERFACE
ip link del $CLIENT_V4_INTERFACE
ip netns del $NS
