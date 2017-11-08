#!/bin/bash

echo "Note: This will take up lots of CPU."
echo "If this freezes, please wait a few minutes; it should come back."

function test() {
	echo "Testing $1 addresses with $2 ports each."
	for i in {1..16}; do
		echo "Test $i"
		sudo insmod pool4-iterations.ko RANGE_COUNT=$1 TADDRS_PER_RANGE=$2
		sudo rmmod pool4-iterations
		sudo dmesg -ct >> results-$1-$2.txt
	done
}

rm -f results*
sudo dmesg -C

test 1 512
test 1 1024
test 1 2048
test 1 4096
test 1 8192
test 1 16384
test 1 32768
test 1 65536
test 2 65536
test 3 65536
test 4 65536
test 5 65536
test 6 65536
test 7 65536
test 8 65536
test 16 65536
test 32 65536

echo "Test results written to result*.txt files."
