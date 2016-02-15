#!/bin/bash

PREFIX=pktgen/
# In high kernels, Linux gets really intrusive and overrides our ID (4, 5),
# which of course also ruins the checksum (10, 11).
# TODO Unfortunately, this means we're not testing all IDs are the same in
# fragments of a same packet in lower kernels.
# TODO It also means we're not testing checksums enough.
# If you know you're running this in a lower kernel, unset this variable and
# the above TODOs will not apply.
NOFRAG_IGNORE=4,5,10,11

function test-single {
	./test-single.sh $PREFIX/sender/$1 $PREFIX/receiver/$2 $3
}

function test-frags {
	./test-frags.sh $PREFIX/sender/$1 $PREFIX/receiver/$2 $3
}

# UDP, 6 -> 4
if [[ -z $1 || $1 = *udp64* ]]; then
	test-single 6-udp-csumok-df 4-udp-csumok-df
	test-single 6-udp-csumfail-df 4-udp-csumfail-df
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
	test-single 6-tcp-csumok-df 4-tcp-csumok-df
	test-single 6-tcp-csumfail-df 4-tcp-csumfail-df
	test-single 6-tcp-csumok-nodf 4-tcp-csumok-nodf $NOFRAG_IGNORE
	test-single 6-tcp-csumfail-nodf 4-tcp-csumfail-nodf $NOFRAG_IGNORE
	test-frags 6-tcp-csumok 4-tcp-csumok $NOFRAG_IGNORE
	test-frags 6-tcp-csumfail 4-tcp-csumfail $NOFRAG_IGNORE
fi

# ICMP info, 6 -> 4
if [[ -z $1 || $1 = *icmpi64* ]]; then
	test-single 6-icmp6info-csumok-df 4-icmp4info-csumok-df
	test-single 6-icmp6info-csumfail-df 4-icmp4info-csumfail-df
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

