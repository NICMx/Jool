#!/bin/bash

echo "Destroying the MAP-T Graybox network..."

ip netns exec client `dirname $0`/setup-client.sh down del
ip netns exec ce     `dirname $0`/setup-ce.sh     down del 0 stop
ip netns exec br     `dirname $0`/setup-br.sh     down del 0 stop
ip netns exec server `dirname $0`/setup-server.sh down del

rmmod graybox

