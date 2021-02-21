#!/bin/sh

#	c111 --+
#	       |
#	      br1 -- ce11 ----+
#	       |              |
#	c112 --+              |
#	                      |
#	c121 ------- ce12 -- br0 -- br -- r4
#                             |
#	c211 ------- ce21 ----+
#
# "br" stands for "Border Relay"
# "br#" stands for "Bridge #"
# "c" is "Client"
# "ce" is "Customer Edge"
# "r#" is "Random #"

if [ $(id -u) != 0 ]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

set -x
set -e

# Variables defined by README

MD1_BMR="2001:db8:4464:1::/64 192.0.2.0/28 1"
MD2_BMR="2001:db8:4464:2::/64 198.51.100.0/28 1"

CE11_EUIP=2001:db8:4464:1:0000::/65
CE11_ADDRL=192.0.2.1
CE12_EUIP=2001:db8:4464:1:8000::/65
CE12_ADDRL=192.0.2.9
CE21_EUIP=2001:db8:4464:2:0000::/65
CE21_ADDRL=198.51.100.1

C111_ADDR=192.0.2.2
C112_ADDR=192.0.2.3
C121_ADDR=192.0.2.10
C211_ADDR=198.51.100.2

# Namespaces and Links

ip netns add c111
ip netns add c112
ip netns add c121
ip netns add c211
ip netns add ce11
ip netns add ce12
ip netns add ce21
ip netns add br
ip netns add r4
brctl addbr br0
ip link set br0 up
brctl addbr br1
ip link set br1 up

connect() {
	NODE1=$1
	NODE2=$2
	ip link add ${NODE1}_${NODE2} type veth peer name ${NODE2}_${NODE1}
	ip link set ${NODE1}_${NODE2} netns ${NODE1}
	ip link set ${NODE2}_${NODE1} netns ${NODE2}
}

connect_bridge() {
	NODE=$1
	BRIDGE=$2
	ip link add ${NODE}_${BRIDGE} type veth peer name ${BRIDGE}_${NODE}
	ip link set ${NODE}_${BRIDGE} netns ${NODE}
	brctl addif ${BRIDGE} ${BRIDGE}_${NODE}
	ip link set ${BRIDGE}_${NODE} up
}

connect_bridge c111 br1
connect_bridge c112 br1
connect_bridge ce11 br1
connect c121 ce12
connect c211 ce21
connect_bridge ce11 br0
connect_bridge ce12 br0
connect_bridge ce21 br0
connect_bridge br br0
connect br r4

# Clients

setup_client() {
	CLIENT=$1
	RIGHT_TARGET=$2
	ADDR=$3
	GATEWAY=$4
	ip netns exec $CLIENT ip address add ${ADDR}/29 dev ${CLIENT}_${RIGHT_TARGET}
	ip netns exec $CLIENT ip link set ${CLIENT}_${RIGHT_TARGET} up
	ip netns exec $CLIENT ip route add default via ${GATEWAY}
}

setup_client c111 br1 $C111_ADDR $CE11_ADDRL
setup_client c112 br1 $C112_ADDR $CE11_ADDRL
setup_client c121 ce12 $C121_ADDR $CE12_ADDRL
setup_client c211 ce21 $C211_ADDR $CE21_ADDRL

# CEs

setup_ce() {
	CE=$1
	ADDR4=$2
	LEFT_TARGET=$3
	ip netns exec $CE ip address add ${ADDR4}/29 dev ${CE}_${LEFT_TARGET}
	ip netns exec $CE ip address add 2001:db8::${CE}/64 dev ${CE}_br0
	ip netns exec $CE ip link set ${CE}_${LEFT_TARGET} up
	ip netns exec $CE ip link set ${CE}_br0 up
	ip netns exec $CE ip route add 64:ff9b::/96 via 2001:db8::1
}

add_route_ce11() {
	ip netns exec $1 ip route add $CE11_EUIP via 2001:db8::ce11
}

add_route_ce12() {
	ip netns exec $1 ip route add $CE12_EUIP via 2001:db8::ce12
}

add_route_ce21() {
	ip netns exec $1 ip route add $CE21_EUIP via 2001:db8::ce21
}

setup_ce ce11 $CE11_ADDRL br1
add_route_ce12 ce11
add_route_ce21 ce11

setup_ce ce12 $CE12_ADDRL c121
add_route_ce11 ce12
add_route_ce21 ce12

setup_ce ce21 $CE21_ADDRL c211
add_route_ce11 ce21
add_route_ce12 ce21

# BR

ip netns exec br ip address add 2001:db8::1/64 dev br_br0
ip netns exec br ip address add 203.0.113.1/24 dev br_r4

ip netns exec br ip link set br_br0 up
ip netns exec br ip link set br_r4 up

add_route_ce11 br
add_route_ce12 br
add_route_ce21 br

# Internet4

ip netns exec r4 ip address add 203.0.113.4/24 dev r4_br
ip netns exec r4 ip link set r4_br up
ip netns exec r4 ip route add 192.0.2.0/28 via 203.0.113.1
ip netns exec r4 ip route add 198.51.100.0/28 via 203.0.113.1

# Tests

sleep 4

test_network() {
	ip netns exec $1 ping -c1 $2
}

test_network c111 $CE11_ADDRL
test_network c112 $CE11_ADDRL
test_network c121 $CE12_ADDRL
test_network c211 $CE21_ADDRL
test_network br   2001:db8::ce11
test_network br   2001:db8::ce12
test_network br   2001:db8::ce21
test_network ce11 2001:db8::ce12
test_network ce11 2001:db8::ce21
test_network ce12 2001:db8::ce21
test_network br   203.0.113.4

# Jool

modprobe jool_mapt

DMR=64:ff9b::/96

add_ce_translator() {
	CE=$1
	EUIP=$2
	BMR6=$3
	BMR4=$4
	EABL=$5

	ip netns exec $CE jool_mapt instance add "$CE" --iptables --dmr $DMR
	ip netns exec $CE jool_mapt -i "$CE" global update end-user-ipv6-prefix $EUIP
	ip netns exec $CE jool_mapt -i "$CE" global update bmr $BMR6 $BMR4 $EABL
	ip netns exec $CE jool_mapt -i "$CE" global update map-t-type CE

	ip netns exec $CE ip6tables -t mangle -A PREROUTING -d $EUIP           -j JOOL_MAPT --instance "$CE"
	ip netns exec $CE iptables  -t mangle -A PREROUTING -d 192.0.2.0/24    -j JOOL_MAPT --instance "$CE"
	ip netns exec $CE iptables  -t mangle -A PREROUTING -d 198.51.100.0/24 -j JOOL_MAPT --instance "$CE"
	ip netns exec $CE iptables  -t mangle -A PREROUTING -d 203.0.113.0/24  -j JOOL_MAPT --instance "$CE"
}

add_ce_translator ce11 $CE11_EUIP $MD1_BMR
add_ce_translator ce12 $CE12_EUIP $MD1_BMR
add_ce_translator ce21 $CE21_EUIP $MD2_BMR

ip netns exec br jool_mapt instance add "br" --iptables --dmr $DMR
ip netns exec br jool_mapt -i "br" fmr add $MD1_BMR
ip netns exec br jool_mapt -i "br" fmr add $MD2_BMR

ip netns exec br ip6tables -t mangle -A PREROUTING -d $DMR            -j JOOL_MAPT --instance "br"
ip netns exec br iptables  -t mangle -A PREROUTING -d 192.0.2.0/24    -j JOOL_MAPT --instance "br"
ip netns exec br iptables  -t mangle -A PREROUTING -d 198.51.100.0/24 -j JOOL_MAPT --instance "br"

# Graybox

insmod ../../../mod/graybox.ko

