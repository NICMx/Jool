#!/bin/bash

if [ -z $1 ]; then
	TESTS=`ls *.ko`
else
	TESTS=$1.ko
fi


for i in $TESTS
do
	echo "Running test '$i'."
	sudo insmod $i && sudo rmmod $i
	sudo dmesg -c | less
done

