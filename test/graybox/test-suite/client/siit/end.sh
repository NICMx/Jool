#!/bin/bash

# Parameters:
# $1: Same as in ./setup.sh.
# $2: Same as in ./setup.sh.

rmmod graybox

ip addr del 198.51.100.2/24 dev $2
ip addr del 2001:db8:1c0:2:21::/64 dev $1
