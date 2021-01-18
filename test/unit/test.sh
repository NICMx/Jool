#!/bin/bash

if [ -z $1 ]; then
	TESTS=`ls -r */*_test.ko`
else
	TESTS=$1/$1.ko
fi
COUNT=0

sudo dmesg -C

set -e
sudo modprobe jool_common
sudo insmod framework/unit.ko
set +e

for i in $TESTS
do
	echo "Running test '$i'."
	sudo insmod $i && sudo rmmod $i
	clear
	# The reason why we're asking the user to q in every test is because
	# a kernel crash could have gone undetected. The idea is that the user
	# would see the massive kernel dump in the output.
	# But the kernel surely exports a means to query wether it has panicked.
	# TODO Figure it out and properly automate this.
	sudo dmesg -ct | less
	COUNT=$((COUNT+1))
done

sudo rmmod unit.ko
sudo modprobe -r jool_common
echo "Ran $COUNT modules."
