#!/bin/bash

if [[ $UID != 0 ]]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

./setup.sh

./test.sh siit
siit_result=$?
./test.sh nat64
nat64_result=$?

./end.sh

if [ $siit_result -ne 0 ]; then
	echo "There was at least one SIIT error."
	exit $siit_result
fi
if [ $nat64_result -ne 0 ]; then
	echo "There was at least one NAT64 error."
	exit $nat64_result
fi
echo "No errors detected."
exit 0
