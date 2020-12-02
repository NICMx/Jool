#!/bin/sh

# Initialize

if [ $(id -u) != 0 ]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

NAME=lt
MD1_BMR="2001:db8:4464:1::/64 192.0.2.0/28 1"
MD2_BMR="2001:db8:4464:2::/64 198.51.100.0/28 1"

GRAYBOX=../../../usr/graybox
IDENTIFICATION=4,5,10,11
INNER_IDENTIFICATION=32,33,38,39

ENABLE_DEBUG=false
ip netns exec ce11 jool_mapt -i ce11 g u logging-debug $ENABLE_DEBUG
ip netns exec ce12 jool_mapt -i ce12 g u logging-debug $ENABLE_DEBUG
ip netns exec ce21 jool_mapt -i ce21 g u logging-debug $ENABLE_DEBUG
ip netns exec  br  jool_mapt -i  br  g u logging-debug $ENABLE_DEBUG
dmesg -C

basic_test() {
	ip netns exec $3 $GRAYBOX expect add `dirname $0`/$4.pkt $5
	ip netns exec $1 $GRAYBOX send `dirname $0`/$2.pkt
	sleep 0.1
	ip netns exec $3 $GRAYBOX expect flush
}

# Tests

for i in ce11 ce12 ce21; do
	ip netns exec $i jool_mapt -i "$i" fmr add $MD1_BMR
	ip netns exec $i jool_mapt -i "$i" fmr add $MD2_BMR
done

if [ -z "$1" -o "$1" = "tcp" ]; then
	basic_test c111 bfv-${NAME}-fmr-c111r4-test   r4   bfv-${NAME}-fmr-c111r4-expected   $IDENTIFICATION
	basic_test c111 bfv-${NAME}-fmr-c111c121-test c121 bfv-${NAME}-fmr-c111c121-expected $IDENTIFICATION
	basic_test c111 bfv-${NAME}-fmr-c111c211-test c211 bfv-${NAME}-fmr-c111c211-expected $IDENTIFICATION
fi

if [ -z "$1" -o "$1" = "icmp-error" ]; then
	basic_test c111 bfv-${NAME}-fmr-c111r4-error-test   br   bfv-${NAME}-fmr-c111r4-error-intermediate
	basic_test c111 bfv-${NAME}-fmr-c111r4-error-test   r4   bfv-${NAME}-fmr-c111r4-error-expected $IDENTIFICATION,$INNER_IDENTIFICATION
	basic_test r4   bfv-${NAME}-fmr-r4c111-error-test   ce11 bfv-${NAME}-fmr-r4c111-error-intermediate
	basic_test r4   bfv-${NAME}-fmr-r4c111-error-test   c111 bfv-${NAME}-fmr-r4c111-error-expected $IDENTIFICATION,$INNER_IDENTIFICATION
	basic_test c111 bfv-${NAME}-fmr-c111c121-error-test ce12 bfv-${NAME}-fmr-c111c121-error-intermediate
	basic_test c111 bfv-${NAME}-fmr-c111c121-error-test c121 bfv-${NAME}-fmr-c111c121-error-expected $IDENTIFICATION,$INNER_IDENTIFICATION
	basic_test c121 bfv-${NAME}-fmr-c121c111-error-test ce11 bfv-${NAME}-fmr-c121c111-error-intermediate
	basic_test c121 bfv-${NAME}-fmr-c121c111-error-test c111 bfv-${NAME}-fmr-c121c111-error-expected $IDENTIFICATION,$INNER_IDENTIFICATION
	basic_test c111 bfv-${NAME}-fmr-c111c211-error-test ce21 bfv-${NAME}-fmr-c111c211-error-intermediate
	basic_test c111 bfv-${NAME}-fmr-c111c211-error-test c211 bfv-${NAME}-fmr-c111c211-error-expected $IDENTIFICATION,$INNER_IDENTIFICATION
	basic_test c211 bfv-${NAME}-fmr-c211c111-error-test ce11 bfv-${NAME}-fmr-c211c111-error-intermediate
	basic_test c211 bfv-${NAME}-fmr-c211c111-error-test c111 bfv-${NAME}-fmr-c211c111-error-expected $IDENTIFICATION,$INNER_IDENTIFICATION
fi

if [ -z "$1" -o "$1" = "6791" ]; then
	basic_test c111 bfv-lt-fmr-c111r4-usu-test br bfv-lt-fmr-c111r4-usu-intermediate
	basic_test c111 bfv-lt-fmr-c111r4-usu-test r4 bfv-lt-fmr-c111r4-usu-expected $IDENTIFICATION,$INNER_IDENTIFICATION
	for i in ce11 br; do
		ip netns exec $i jool_mapt -i "$i" global update rfc6791v6-prefix 2001:db8::ffff
		ip netns exec $i jool_mapt -i "$i" global update rfc6791v4-prefix 192.0.2.255
	done
	basic_test c111 bfv-lt-fmr-c111r4-usu-test br bfv-lt-fmr-c111r4-usp-intermediate
	basic_test c111 bfv-lt-fmr-c111r4-usu-test r4 bfv-lt-fmr-c111r4-usp-expected $IDENTIFICATION,$INNER_IDENTIFICATION
	for i in ce11 br; do
		ip netns exec $i jool_mapt -i "$i" global update rfc6791v6-prefix null
		ip netns exec $i jool_mapt -i "$i" global update rfc6791v4-prefix null
	done
fi


for i in ce11 ce12 ce21; do
	ip netns exec $i jool_mapt -i "$i" fmr flush
done

if [ -z "$1" -o "$1" = "nofmr" ]; then
	basic_test c111 bfv-${NAME}-fmr-c111r4-test     r4   bfv-${NAME}-fmr-c111r4-expected     $IDENTIFICATION
	basic_test c111 bfv-${NAME}-nofmr-c111c121-test c121 bfv-${NAME}-nofmr-c111c121-expected $IDENTIFICATION
	basic_test c111 bfv-${NAME}-nofmr-c111c211-test c211 bfv-${NAME}-nofmr-c111c211-expected $IDENTIFICATION
fi

# Output Results

dmesg -tc
$GRAYBOX stats display
$GRAYBOX stats flush

