#!/bin/bash

# Parameters:
# $1: Same as in ./setup.sh.
# $2: Same as in ./setup.sh.

rmmod graybox

ip addr del 192.0.2.5/24 dev $2
ip addr del 2001:db8::5/96 dev $1
