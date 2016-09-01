#!/bin/bash

# What is this for?
# The test script is normally run as part of another script, which
# likely just configured the interfaces, and so the neighbors might
# still be discovering each other.
# If we run the tests while the neighbors are stil exchanging
# handshakes or whatever, the test packets can disappear.
# These pings should sleep us until we know a packet can do a full
# round-trip.

echo "Waiting for the network to be ready..."

for i in {1..10}; do
	ping6 $1 -c 1 > /dev/null
	if [ $? -eq 0 ]; then
		echo "Ready."
		exit 0
	fi
	sleep 1
done

echo "It appears the network hasn't been configured."
echo "Quitting."
exit 1

