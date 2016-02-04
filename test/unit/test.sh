#!/bin/bash

if [ -z $1 ]; then
	TESTS=`ls -r */*.ko`
else
	TESTS=$1/$1.ko
fi


for i in $TESTS
do
	echo "Running test '$i'."
	sudo insmod $i && sudo rmmod $i
	clear
	sudo dmesg -ct | less
done

