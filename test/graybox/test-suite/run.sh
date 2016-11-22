#!/bin/bash


# Runs the entire test suite contained in this folder.
#
# Will print results in standard output and return nonzero if at least one test
# failed.


if [[ $UID != 0 ]]; then
	echo "Please start the script as root or sudo."
	exit 1
fi


# Arguments:
# $1: Either "siit" or "nat64", depending on which tests you want to run.
#     (No quotes.)
# $2: Argument to client/$1/send.sh. See client/$1/send.sh.
function run-tests {
	./network-create.sh $1
	client/$1/send.sh $2
	result=$?
	./network-destroy.sh $1
	return $result
}


./namespace-create.sh

run-tests siit
siit_result=$?
run-tests nat64
nat64_result=$?

./namespace-destroy.sh


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
