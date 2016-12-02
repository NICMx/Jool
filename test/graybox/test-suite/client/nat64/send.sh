#!/bin/bash


# Arguments:
# $1: List of test names you want to run, separated by any character.
#     Example: "udp64, tcp46, icmpe64"
#     If this argument is unspecified, the script will run all the tests.
#     The current test names are:
#     udp64: IPv6->IPv4 UDP tests
#     udp46: IPv4->IPv6 UDP tests
#     tcp64: IPv6->IPv4 TCP tests
#     icmpi64: IPv6->IPv4 ICMP ping tests
#     icmpi46: IPv4->IPv6 ICMP ping tests
#     icmpe64: IPv6->IPv4 ICMP error tests
#     icmpe46: IPv4->IPv6 ICMP error tests
#     issue: Random tests, correlated to bug reports that have been reported in
#            the past.


GRAYBOX=`dirname $0`/../../../usr/graybox
PREFIX=`dirname $0`/pktgen
# When there's no fragmentation, Jool is supposed to randomize the
# fragment ID (bytes 4 and 5) so we can't validate it.
# The ID's randomization cascades to the checksum. (Bytes 10 and
# 11.)
NOFRAG_IGNORE=4,5,10,11

function test-simple {
	$GRAYBOX expect add `dirname $0`/$2.pkt $3
	$GRAYBOX send `dirname $0`/$1.pkt
	sleep 0.1
	$GRAYBOX expect flush
}

function test-single {
	$GRAYBOX expect add $PREFIX/receiver/$2-nofrag.pkt $3
	$GRAYBOX send $PREFIX/sender/$1-nofrag.pkt
	sleep 0.1
	$GRAYBOX expect flush
}

function test-frags {
	$GRAYBOX expect add $PREFIX/receiver/$2-nodf-frag0.pkt $3
	$GRAYBOX expect add $PREFIX/receiver/$2-nodf-frag1.pkt $3
	$GRAYBOX expect add $PREFIX/receiver/$2-nodf-frag2.pkt $3
	$GRAYBOX send $PREFIX/sender/$1-nodf-frag0.pkt
	$GRAYBOX send $PREFIX/sender/$1-nodf-frag1.pkt
	$GRAYBOX send $PREFIX/sender/$1-nodf-frag2.pkt
	sleep 0.1
	$GRAYBOX expect flush
}


`dirname $0`/../wait.sh 64:ff9b::192.0.2.5
if [ $? -ne 0 ]; then
	exit 1
fi

echo "Testing! Please wait..."


# UDP, 6 -> 4
if [[ -z $1 || $1 = *udp64* ]]; then
	test-single 6-udp-csumok-df 4-udp-csumok-df $NOFRAG_IGNORE
	test-single 6-udp-csumfail-df 4-udp-csumfail-df $NOFRAG_IGNORE
	test-single 6-udp-csumok-nodf 4-udp-csumok-nodf $NOFRAG_IGNORE
	test-single 6-udp-csumfail-nodf 4-udp-csumfail-nodf $NOFRAG_IGNORE
	test-frags 6-udp-csumok 4-udp-csumok $NOFRAG_IGNORE
	test-frags 6-udp-csumfail 4-udp-csumfail $NOFRAG_IGNORE
fi

# UDP, 4 -> 6
if [[ -z $1 || $1 = *udp46* ]]; then
	test-single 4-udp-csumok-df 6-udp-csumok-df
	test-single 4-udp-csumfail-df 6-udp-csumfail-df
	test-single 4-udp-csumok-nodf 6-udp-csumok-nodf
	test-single 4-udp-csumfail-nodf 6-udp-csumfail-nodf
	test-frags 4-udp-csumok 6-udp-csumok 44,45,46,47
	test-frags 4-udp-csumfail 6-udp-csumfail 44,45,46,47
fi

# TCP
if [[ -z $1 || $1 = *tcp64* ]]; then
	test-single 6-tcp-csumok-df 4-tcp-csumok-df $NOFRAG_IGNORE
	test-single 6-tcp-csumfail-df 4-tcp-csumfail-df $NOFRAG_IGNORE
	test-single 6-tcp-csumok-nodf 4-tcp-csumok-nodf $NOFRAG_IGNORE
	test-single 6-tcp-csumfail-nodf 4-tcp-csumfail-nodf $NOFRAG_IGNORE
	test-frags 6-tcp-csumok 4-tcp-csumok $NOFRAG_IGNORE
	test-frags 6-tcp-csumfail 4-tcp-csumfail $NOFRAG_IGNORE
fi

# ICMP info, 6 -> 4
if [[ -z $1 || $1 = *icmpi64* ]]; then
	test-single 6-icmp6info-csumok-df 4-icmp4info-csumok-df $NOFRAG_IGNORE
	test-single 6-icmp6info-csumfail-df 4-icmp4info-csumfail-df $NOFRAG_IGNORE
	test-single 6-icmp6info-csumok-nodf 4-icmp4info-csumok-nodf $NOFRAG_IGNORE
	test-single 6-icmp6info-csumfail-nodf 4-icmp4info-csumfail-nodf $NOFRAG_IGNORE
	test-frags 6-icmp6info-csumok 4-icmp4info-csumok $NOFRAG_IGNORE
	test-frags 6-icmp6info-csumfail 4-icmp4info-csumfail $NOFRAG_IGNORE
fi

# ICMP info, 4 -> 6
if [[ -z $1 || $1 = *icmpi46* ]]; then
	test-single 4-icmp4info-csumok-df 6-icmp6info-csumok-df
	test-single 4-icmp4info-csumfail-df 6-icmp6info-csumfail-df
	test-single 4-icmp4info-csumok-nodf 6-icmp6info-csumok-nodf
	test-single 4-icmp4info-csumfail-nodf 6-icmp6info-csumfail-nodf
	test-frags 4-icmp4info-csumok 6-icmp6info-csumok 44,45,46,47
	test-frags 4-icmp4info-csumfail 6-icmp6info-csumfail 44,45,46,47
fi

# ICMP error, 6 -> 4
if [[ -z $1 || $1 = *icmpe64* ]]; then
	# 32, 33, 38 and 39 are inner IDs and checksums.
	test-single 6-icmp6err-csumok-df 4-icmp4err-csumok-df 4,5,10,11,32,33,38,39
	test-single 6-icmp6err-csumok-nodf 4-icmp4err-csumok-nodf $NOFRAG_IGNORE,32,33,38,39
fi

# ICMP error, 4 -> 6
if [[ -z $1 || $1 = *icmpe46* ]]; then
	test-single 4-icmp4err-csumok-df 6-icmp6err-csumok-df
	test-single 4-icmp4err-csumok-nodf 6-icmp6err-csumok-nodf
fi

# Issue-specific tests
if [[ -z $1 || $1 = *issue* ]]; then
	ip netns exec joolns jool --source-icmpv6-errors-better on
	# TODO The IPv4 node is returning DSCP 0x30. I don't know why.
	test-simple manual/issue132-test manual/issue132-expected-on 0
	ip netns exec joolns jool --source-icmpv6-errors-better off
	# TODO The IPv4 node is returning DSCP 0x30. I don't know why.
	test-simple manual/issue132-test manual/issue132-expected-off 0
fi

$GRAYBOX stats display
result=$?
$GRAYBOX stats flush

exit $result
