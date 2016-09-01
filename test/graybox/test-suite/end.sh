#!/bin/bash

# Destroys the stuff setup.sh created.

. config

ip link del $CLIENT_V6_INTERFACE
ip link del $CLIENT_V4_INTERFACE
ip netns del $NS
