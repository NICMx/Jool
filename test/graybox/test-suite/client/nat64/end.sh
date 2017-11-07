#!/bin/bash

# Parameters:
# $1: Same as in ./setup.sh.
# $2: Same as in ./setup.sh.

rmmod graybox

ip addr flush dev $1 scope global
ip addr flush dev $2 scope global
