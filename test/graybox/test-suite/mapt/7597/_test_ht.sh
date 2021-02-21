#!/bin/sh

# Initialize

if [ $(id -u) != 0 ]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

NAME=ht
MD1_BMR="2001:db8:4464:1::/64 192.0.2.0/28 8"
MD2_BMR="2001:db8:4464:2::/64 198.51.100.0/28 8"

GRAYBOX=../../../usr/graybox
IDENTIFICATION=4,5,10,11
INNER_IDENTIFICATION=32,33,38,39

ENABLE_DEBUG=false
ip netns exec ce11t jool_mapt -i ce11t g u logging-debug $ENABLE_DEBUG
ip netns exec ce12t jool_mapt -i ce12t g u logging-debug $ENABLE_DEBUG
ip netns exec ce21t jool_mapt -i ce21t g u logging-debug $ENABLE_DEBUG
ip netns exec  br   jool_mapt -i  br   g u logging-debug $ENABLE_DEBUG
dmesg -C

basic_test() {
	ip netns exec $3 $GRAYBOX expect add `dirname $0`/$4.pkt $5
	ip netns exec $1 $GRAYBOX send `dirname $0`/$2.pkt
	sleep 0.1
	ip netns exec $3 $GRAYBOX expect flush
}

# Tests

for i in ce11t ce12t ce21t; do
	ip netns exec $i jool_mapt -i "$i" fmr add $MD1_BMR
	ip netns exec $i jool_mapt -i "$i" fmr add $MD2_BMR
done

basic_test c111 bfv-${NAME}-fmr-c111r4-test   r4   bfv-${NAME}-fmr-c111r4-expected   $IDENTIFICATION
basic_test c111 bfv-${NAME}-fmr-c111c112-test c112 bfv-${NAME}-fmr-c111c112-expected $IDENTIFICATION
basic_test c111 bfv-${NAME}-fmr-c111c121-test c121 bfv-${NAME}-fmr-c111c121-expected $IDENTIFICATION
basic_test c111 bfv-${NAME}-fmr-c111c211-test c211 bfv-${NAME}-fmr-c111c211-expected $IDENTIFICATION

for i in ce11t ce12t ce21t; do
	ip netns exec $i jool_mapt -i "$i" fmr flush
done

basic_test c111 bfv-${NAME}-fmr-c111r4-test     r4   bfv-${NAME}-fmr-c111r4-expected     $IDENTIFICATION
basic_test c111 bfv-${NAME}-nofmr-c111c112-test c112 bfv-${NAME}-nofmr-c111c112-expected $IDENTIFICATION
basic_test c111 bfv-${NAME}-nofmr-c111c121-test c121 bfv-${NAME}-nofmr-c111c121-expected $IDENTIFICATION
basic_test c111 bfv-${NAME}-nofmr-c111c211-test c211 bfv-${NAME}-nofmr-c111c211-expected $IDENTIFICATION

# Output Results

dmesg -tc
$GRAYBOX stats display
$GRAYBOX stats flush

