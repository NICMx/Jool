#!/bin/bash

TESTS=`ls *.ko`

for i in $TESTS
do
	echo "Running test '$i'."
	sudo insmod $i && sudo rmmod $i
	dmesg | tail
	read -p 'press [ENTER] to continue.'
done

