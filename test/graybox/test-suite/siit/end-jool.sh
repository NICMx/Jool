#!/bin/sh

if [ $(id -u) != 0 ]; then
	echo "Sorry; I need more privileges."
	exit 1
fi

rmmod joolif
rmmod graybox
