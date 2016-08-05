#!/bin/bash

if [ -z $1 ]; then
	TESTS=`ls -r */*.ko`
else
	TESTS=$1/$1.ko
fi
COUNT=0

sudo dmesg -C

for i in $TESTS
do
	echo "Running test '$i'."
	sudo insmod $i && sudo rmmod $i
	clear
	sudo dmesg -ct | less
	COUNT=$((COUNT+1))
done

echo "Ran $COUNT modules."
