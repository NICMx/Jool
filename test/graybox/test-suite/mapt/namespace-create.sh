#!/bin/sh

echo "Preparing the MAP-T Graybox network namespaces..."

if ip netns list | grep 'ce' > /dev/null; then
	echo "The namespaces seem to already exist. Skipping step."
	exit 0
fi

ip netns add client
ip netns add ce
ip netns add br
ip netns add server

ip link add client2ce netns client type veth peer ce2client netns ce
ip link add ce2br     netns ce     type veth peer br2ce     netns br
ip link add br2server netns br     type veth peer server2br netns server

