#!/bin/bash

TESTS=`ls *.ko`

for i in $TESTS
do
	echo "Running test '$i'."
	sudo insmod $i && sudo rmmod $i
	sudo dmesg -c | less
done

