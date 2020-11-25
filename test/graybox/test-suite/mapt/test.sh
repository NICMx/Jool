#!/bin/sh


# Arguments:
# $1: List of the names of the test groups you want to run, separated by any
#     character.
#     Example: "basic"
#     If this argument is unspecified, the script will run all the tests.


GRAYBOX=`dirname $0`/../../usr/graybox

# When Linux creates an ICMPv4 error on behalf of Jool, it writes 'c0' on the
# outer TOS field for me. This seems to mean "Network Control" messages
# according to DSCP, which is probably fair. Since TOS 0 would also be correct,
# we'll just accept whatever.
TOS=1
# The translated IPv4 identification is always random, so it should be always
# ignored during validation. Unfortunately, of course, the header checksum is
# also affected.
IDENTIFICATION=4,5,10,11
INNER_IDENTIFICATION=32,33,38,39

#`dirname $0`/../wait.sh 2001:db8:1c6:3364:2::
#if [ $? -ne 0 ]; then
#	exit 1
#fi

echo "Testing! Please wait..."

basic_test() {
	ip netns exec $3 $GRAYBOX expect add `dirname $0`/pkt/$4.pkt $5
	ip netns exec $1 $GRAYBOX send `dirname $0`/pkt/$2.pkt
	sleep 0.1
	ip netns exec $3 $GRAYBOX expect flush
}

if [ -z "$1" -o "$1" = "basic" ]; then
	basic_test client aat br     aae1
	basic_test client aat server aae2 $IDENTIFICATION
	basic_test server abt ce     abe1
	basic_test server abt client abe2 $IDENTIFICATION

	basic_test client act br     ace1
	basic_test client act server ace2 $IDENTIFICATION
	basic_test server adt ce     ade1
	basic_test server adt client ade2 $IDENTIFICATION

	basic_test client aet br     aee1
	basic_test client aet server aee2 $IDENTIFICATION
	basic_test server aft ce     afe1
	basic_test server aft client afe2 $IDENTIFICATION

	basic_test client agt br     age1
	basic_test client agt server age2 $IDENTIFICATION,$INNER_IDENTIFICATION
	basic_test server aht ce     ahe1
	basic_test server aht client ahe2 $IDENTIFICATION,$INNER_IDENTIFICATION
fi

#if [ -z "$1" -o "$1" = "new" ]; then
#fi

$GRAYBOX stats display
result=$?
$GRAYBOX stats flush

exit $result
