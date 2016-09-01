#!/bin/bash

if [[ $UID != 0 ]]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

./setup.sh
./test.sh siit
./test.sh nat64
./end.sh
