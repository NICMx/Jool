#!/bin/bash


GRAYBOX=`dirname $0`/../../../usr/graybox


function test-single {
	$GRAYBOX expect add $2-expected.pkt $3
	$GRAYBOX send $1-test.pkt
	sleep 0.1
	$GRAYBOX expect flush
}


test-single manual/igmp64 4,5,10,11
test-single manual/igmp46
test-single manual/6791 4,5,10,11,32,33,38,39


graybox stats display
graybox stats flush

