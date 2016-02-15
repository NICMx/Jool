#!/bin/bash

FRAGS=graybox
PREFIX=pktgen


function test-single {
	if [ -n "${3+x}" ]; then $FRAGS -ga --numArray $3; fi
	$FRAGS -ra --pkt $PREFIX/receiver/$2.pkt
	$FRAGS -sa --pkt $PREFIX/sender/$1.pkt
	sleep 0.1
	if [ -n "${3+x}" ]; then $FRAGS -gf; fi
	$FRAGS -rf
}

function test-frag {
	$FRAGS -ra --pkt $PREFIX/receiver/$2.pkt
	$FRAGS -ra --pkt $PREFIX/receiver/$3.pkt
	$FRAGS -sa --pkt $PREFIX/sender/$1.pkt
	sleep 0.1
	$FRAGS -rf
}


# UDP, 6 -> 4
if [[ -z $1 || $1 = *udp64* ]]; then
	test-single 6-udp-csumok-df-nofrag 4-udp-csumok-df-nofrag
	test-single 6-udp-csumok-nodf-nofrag 4-udp-csumok-nodf-nofrag
	test-single 6-udp-csumok-nodf-frag0 4-udp-csumok-nodf-frag0
	test-single 6-udp-csumok-nodf-frag1 4-udp-csumok-nodf-frag1
	test-single 6-udp-csumok-nodf-frag2 4-udp-csumok-nodf-frag2

	test-single 6-udp-csumfail-df-nofrag 4-udp-csumfail-df-nofrag
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
	test-single 6-tcp-csumok-df-nofrag 4-tcp-csumok-df-nofrag
	test-single 6-tcp-csumok-nodf-nofrag 4-tcp-csumok-nodf-nofrag
	test-single 6-tcp-csumok-nodf-frag0 4-tcp-csumok-nodf-frag0
	test-single 6-tcp-csumok-nodf-frag1 4-tcp-csumok-nodf-frag1
	test-single 6-tcp-csumok-nodf-frag2 4-tcp-csumok-nodf-frag2

	test-single 6-tcp-csumfail-df-nofrag 4-tcp-csumfail-df-nofrag
	test-single 6-tcp-csumfail-nodf-nofrag 4-tcp-csumfail-nodf-nofrag
	test-single 6-tcp-csumfail-nodf-frag0 4-tcp-csumfail-nodf-frag0
	test-single 6-tcp-csumfail-nodf-frag1 4-tcp-csumfail-nodf-frag1
	test-single 6-tcp-csumfail-nodf-frag2 4-tcp-csumfail-nodf-frag2
fi

# ICMP info, 6 -> 4
if [[ -z $1 || $1 = *icmpi64* ]]; then
	test-single 6-icmp6info-csumok-df-nofrag 4-icmp4info-csumok-df-nofrag
	test-single 6-icmp6info-csumok-nodf-nofrag 4-icmp4info-csumok-nodf-nofrag

	test-single 6-icmp6info-csumfail-df-nofrag 4-icmp4info-csumfail-df-nofrag
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

