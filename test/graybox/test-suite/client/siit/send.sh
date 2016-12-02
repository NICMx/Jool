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


GRAYBOX=`dirname $0`/../../../usr/graybox
PREFIX=`dirname $0`/pktgen
# When there's no fragmentation, Jool is supposed to randomize the
# fragment ID (bytes 4 and 5) so we can't validate it.
# The ID's randomization cascades to the checksum. (Bytes 10 and
# 11.)
NOFRAG_IGNORE=4,5,10,11

function test-single {
	$GRAYBOX expect add $PREFIX/receiver/$2.pkt $3
	$GRAYBOX send $PREFIX/sender/$1.pkt
	sleep 0.1
	$GRAYBOX expect flush
}

function test-frag {
	$GRAYBOX expect add $PREFIX/receiver/$2.pkt
	$GRAYBOX expect add $PREFIX/receiver/$3.pkt
	$GRAYBOX send $PREFIX/sender/$1.pkt
	sleep 0.1
	$GRAYBOX expect flush
}


`dirname $0`/../wait.sh 2001:db8:1c6:3364:2::
if [ $? -ne 0 ]; then
	exit 1
fi

echo "Testing! Please wait..."


# UDP, 6 -> 4
if [[ -z $1 || $1 = *udp64* ]]; then
	test-single 6-udp-csumok-df-nofrag 4-udp-csumok-df-nofrag $NOFRAG_IGNORE
	test-single 6-udp-csumok-nodf-nofrag 4-udp-csumok-nodf-nofrag
	test-single 6-udp-csumok-nodf-frag0 4-udp-csumok-nodf-frag0
	test-single 6-udp-csumok-nodf-frag1 4-udp-csumok-nodf-frag1
	test-single 6-udp-csumok-nodf-frag2 4-udp-csumok-nodf-frag2

	test-single 6-udp-csumfail-df-nofrag 4-udp-csumfail-df-nofrag $NOFRAG_IGNORE
	test-single 6-udp-csumfail-nodf-nofrag 4-udp-csumfail-nodf-nofrag
	test-single 6-udp-csumfail-nodf-frag0 4-udp-csumfail-nodf-frag0
	test-single 6-udp-csumfail-nodf-frag1 4-udp-csumfail-nodf-frag1
	test-single 6-udp-csumfail-nodf-frag2 4-udp-csumfail-nodf-frag2
fi

# UDP, 4 -> 6
if [[ -z $1 || $1 = *udp46* ]]; then
	test-single 4-udp-csumok-df-nofrag 6-udp-csumok-df-nofrag
	test-single 4-udp-csumok-nodf-nofrag 6-udp-csumok-nodf-nofrag
	test-single 4-udp-csumok-nodf-frag0 6-udp-csumok-nodf-frag0
	test-single 4-udp-csumok-nodf-frag1 6-udp-csumok-nodf-frag1
	test-single 4-udp-csumok-nodf-frag2 6-udp-csumok-nodf-frag2

	test-single 4-udp-csumfail-df-nofrag 6-udp-csumfail-df-nofrag
	test-single 4-udp-csumfail-nodf-nofrag 6-udp-csumfail-nodf-nofrag
	test-single 4-udp-csumfail-nodf-frag0 6-udp-csumfail-nodf-frag0
	test-single 4-udp-csumfail-nodf-frag1 6-udp-csumfail-nodf-frag1
	test-single 4-udp-csumfail-nodf-frag2 6-udp-csumfail-nodf-frag2
fi

# TCP, 6 -> 4
if [[ -z $1 || $1 = *tcp64* ]]; then
	test-single 6-tcp-csumok-df-nofrag 4-tcp-csumok-df-nofrag $NOFRAG_IGNORE
	test-single 6-tcp-csumok-nodf-nofrag 4-tcp-csumok-nodf-nofrag
	test-single 6-tcp-csumok-nodf-frag0 4-tcp-csumok-nodf-frag0
	test-single 6-tcp-csumok-nodf-frag1 4-tcp-csumok-nodf-frag1
	test-single 6-tcp-csumok-nodf-frag2 4-tcp-csumok-nodf-frag2

	test-single 6-tcp-csumfail-df-nofrag 4-tcp-csumfail-df-nofrag $NOFRAG_IGNORE
	test-single 6-tcp-csumfail-nodf-nofrag 4-tcp-csumfail-nodf-nofrag
	test-single 6-tcp-csumfail-nodf-frag0 4-tcp-csumfail-nodf-frag0
	test-single 6-tcp-csumfail-nodf-frag1 4-tcp-csumfail-nodf-frag1
	test-single 6-tcp-csumfail-nodf-frag2 4-tcp-csumfail-nodf-frag2
fi

# ICMP info, 6 -> 4
if [[ -z $1 || $1 = *icmpi64* ]]; then
	test-single 6-icmp6info-csumok-df-nofrag 4-icmp4info-csumok-df-nofrag $NOFRAG_IGNORE
	test-single 6-icmp6info-csumok-nodf-nofrag 4-icmp4info-csumok-nodf-nofrag

	test-single 6-icmp6info-csumfail-df-nofrag 4-icmp4info-csumfail-df-nofrag $NOFRAG_IGNORE
	test-single 6-icmp6info-csumfail-nodf-nofrag 4-icmp4info-csumfail-nodf-nofrag
fi

# ICMP info, 4 -> 6
if [[ -z $1 || $1 = *icmpi46* ]]; then
	test-single 4-icmp4info-csumok-df-nofrag 6-icmp6info-csumok-df-nofrag
	test-single 4-icmp4info-csumok-nodf-nofrag 6-icmp6info-csumok-nodf-nofrag

	test-single 4-icmp4info-csumfail-df-nofrag 6-icmp6info-csumfail-df-nofrag
	test-single 4-icmp4info-csumfail-nodf-nofrag 6-icmp6info-csumfail-nodf-nofrag
fi

# ICMP error, 6 -> 4
if [[ -z $1 || $1 = *icmpe64* ]]; then
	# 4,5 = frag id. Jool has to assign something random, hence we don't expect anything.
	# 10,11 = IPv4 csum. Inherits frag id's randomness.
	# 22,23 = ICMP csum. Inherits the followind fields' randomness.
	# 32,33 = inner frag id. Same as above.
	# 34 = inner DF. An atomic fragments free Jool has no way to know the DF of the original packet.
	# 38,39 = inner IPv4 csum. Inherits other field's randomness.
	test-single 6-icmp6err-csumok-df-nofrag 4-icmp4err-csumok-df-nofrag 4,5,10,11,22,23,32,33,34,38,39
	# This one doesn't have ignored bytes because DF and IDs have to be inferred from the fragment headers.
	test-single 6-icmp6err-csumok-nodf-nofrag 4-icmp4err-csumok-nodf-nofrag
fi

# ICMP error, 4 -> 6
if [[ -z $1 || $1 = *icmpe46* ]]; then
	test-single 4-icmp4err-csumok-df-nofrag 6-icmp6err-csumok-df-nofrag
	test-single 4-icmp4err-csumok-nodf-nofrag 6-icmp6err-csumok-nodf-nofrag
fi

# Others
#if [[ -z $1 || $1 = *other* ]]; then
	# TODO mangle the packet size so this doesn't have so many exceptions.
	#test-single frag-icmp6 frag-icmp6 4,5,6,10,11,22,23,32,33,34,38,39,54,55
	#test-single frag-icmp4 frag-icmp4
	#test-single frag-minmtu6-big frag-minmtu6-big0 frag-minmtu6-big1
#fi

$GRAYBOX stats display
result=$?
$GRAYBOX stats flush

exit $result
