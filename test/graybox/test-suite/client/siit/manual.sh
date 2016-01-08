#!/bin/bash


# test-frags 4-udp-csumok-nodf 6-udp-csumok-nodf
# test-frags 4-udp-csumfail-nodf 6-udp-csumfail-nodf


./test-single.sh manual/igmp6-sender manual/igmp4-receiver 4,5,10,11
./test-single.sh manual/igmp4-sender manual/igmp6-receiver

#NAT64/tests/graybox/usr/graybox -sa --pkt manual/error-addresses-test.pkt
#NAT64/tests/graybox/usr/graybox -sa --pkt manual/loop.pkt

