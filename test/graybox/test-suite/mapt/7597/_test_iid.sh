#!/bin/sh

# Initialize

if [ $(id -u) != 0 ]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

NAME=ht
MD1_BMR="2001:db8:4464:1::/112 192.0.2.0/24 16"
MD2_BMR="2001:db8:4464:2::/112 198.51.100.0/24 16"

GRAYBOX=../../../usr/graybox
IDENTIFICATION=4,5,10,11
INNER_IDENTIFICATION=32,33,38,39

ENABLE_DEBUG=true
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

basic_test c111 iid-c111r4-test   br    iid-c111r4-intermediate
basic_test c111 iid-c111r4-test   r4    iid-c111r4-expected       $IDENTIFICATION
basic_test c111 iid-c111c112-test c112  iid-c111c112-expected     $IDENTIFICATION
basic_test c111 iid-c111c121-test ce12t iid-c111c121-intermediate
basic_test c111 iid-c111c121-test c121  iid-c111c121-expected     $IDENTIFICATION
basic_test c111 iid-c111c211-test ce21t iid-c111c211-intermediate
basic_test c111 iid-c111c211-test c211  iid-c111c211-expected     $IDENTIFICATION

for i in ce11t ce12t ce21t; do
	ip netns exec $i jool_mapt -i "$i" fmr flush
done

# Output Results

dmesg -tc
$GRAYBOX stats display
$GRAYBOX stats flush

