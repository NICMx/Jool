#!/bin/sh


# Runs the entire Graybox test suite.
#
# Will print results in standard output and return nonzero if at least one test
# failed.


if [ $(id -u) != 0 ]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

if [ -z "$1" ]; then
	NAT64="jool"
	SIIT="jool_siit"
else
	NAT64="$1/jool"
	SIIT="$1/jool_siit"
fi

./namespace-create.sh

siit/setup.sh "$SIIT"
siit/test.sh "" "$SIIT"
siit_result=$?
siit/end.sh

nat64/setup.sh "$NAT64"
nat64/test.sh "" "$NAT64"
nat64_result=$?
nat64/end.sh

./namespace-destroy.sh


if [ $siit_result -ne 0 ]; then
	exit $siit_result
fi
if [ $nat64_result -ne 0 ]; then
	exit $nat64_result
fi
echo "No errors detected."
exit 0
