#!/bin/sh

echo "Destroying the MAP-T Graybox network namespaces..."

ip netns del client
ip netns del ce
ip netns del br
ip netns del server
