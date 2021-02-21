#!/bin/bash

echo "Preparing the MAP-T Graybox network..."

ip netns exec client `dirname $0`/setup-client.sh up add
ip netns exec ce     `dirname $0`/setup-ce.sh     up add 1 start
ip netns exec br     `dirname $0`/setup-br.sh     up add 1 start
ip netns exec server `dirname $0`/setup-server.sh up add

insmod `dirname $0`/../../mod/graybox.ko

