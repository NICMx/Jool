#!/bin/bash

ip6tables -t mangle -F
iptables  -t mangle -F

modprobe -rq jool_siit
modprobe -rq jool
