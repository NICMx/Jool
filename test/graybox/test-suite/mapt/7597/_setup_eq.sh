#!/bin/sh

#	c111 --+
#	       |
#	      br1 -- ce11n -- ce11t ----+
#	       |                        |
#	c112 --+                        |
#	                                |
#	c121 ------- ce12n -- ce12t -- br0 -- br -- r4
#                                       |
#	c211 ------- ce21n -- ce12t ----+
#
# "br" stands for "Border Relay"
# "br#" stands for "Bridge #"
# "c" is "Client"
# "ce##n" is "Customer Edge ## NAT"
# "ce##t" is "Customer Edge ## translator"
# "r#" is "Random #"

if [ $(id -u) != 0 ]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

set -x
set -e

# Variables defined by README

MD1_BMR="2001:db8:4464:1::/64 192.0.2.0/24 8"
MD2_BMR="2001:db8:4464:2::/64 198.51.100.0/24 8"

CE11_EUIP=2001:db8:4464:1:100::/72
CE11_ADDR4=192.0.2.1
CE11_ADDRL=192.168.0.1
CE12_EUIP=2001:db8:4464:1:200::/72
CE12_ADDR4=192.0.2.2
CE12_ADDRL=192.168.0.1
CE21_EUIP=2001:db8:4464:2:100::/72
CE21_ADDR4=198.51.100.1
CE21_ADDRL=192.168.0.1

C111_ADDR=192.168.0.2
C112_ADDR=192.168.0.3
C121_ADDR=192.168.0.2
C211_ADDR=192.168.0.2

# Namespaces and Links

ip netns add c111
ip netns add c112
ip netns add c121
ip netns add c211
ip netns add ce11n
ip netns add ce12n
ip netns add ce21n
ip netns add ce11t
ip netns add ce12t
ip netns add ce21t
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
connect_bridge ce11n br1
connect c121 ce12n
connect c211 ce21n

connect ce11n ce11t
connect ce12n ce12t
connect ce21n ce21t

connect_bridge ce11t br0
connect_bridge ce12t br0
connect_bridge ce21t br0
connect_bridge br br0

connect br r4

# Client addresses and routes

setup_client() {
	CLIENT=$1
	RIGHT_TARGET=$2
	ADDR=$3
	GATEWAY=$4
	ip netns exec $CLIENT ip address add ${ADDR}/24 dev ${CLIENT}_${RIGHT_TARGET}
	ip netns exec $CLIENT ip link set ${CLIENT}_${RIGHT_TARGET} up
	ip netns exec $CLIENT ip route add default via ${GATEWAY}
}

setup_client c111 br1 $C111_ADDR $CE11_ADDRL
setup_client c112 br1 $C112_ADDR $CE11_ADDRL
setup_client c121 ce12n $C121_ADDR $CE12_ADDRL
setup_client c211 ce21n $C211_ADDR $CE21_ADDRL

# CE (NAT) addresses and routes

setup_ce_nat() {
	NAME=$1
	NEIGHBOR_LEFT=$2
	ADDR_LEFT=$3
	TO_SOURCE=$4

	ip netns exec ${NAME}n ip address add ${ADDR_LEFT}/24 dev ${NAME}n_${NEIGHBOR_LEFT}
	ip netns exec ${NAME}n ip link set ${NAME}n_${NEIGHBOR_LEFT} up

	ip netns exec ${NAME}n ip address add 10.0.0.2/24 dev ${NAME}n_${NAME}t
	ip netns exec ${NAME}n ip link set ${NAME}n_${NAME}t up
	ip netns exec ${NAME}n ip route add default via 10.0.0.1
	
	ip netns exec ${NAME}n /sbin/sysctl -w net.ipv4.conf.all.forwarding=1
	ip netns exec ${NAME}n /sbin/sysctl -w net.ipv6.conf.all.forwarding=1
}

setup_ce_nat ce11 br1  $CE11_ADDRL
setup_ce_nat ce12 c121 $CE12_ADDRL
setup_ce_nat ce21 c211 $CE21_ADDRL

# CE (translator) addresses and routes

setup_ce_xlat() {
	NAME=$1
	NAT_ADDR=$2

	ip netns exec ${NAME}t ip address add 10.0.0.1/24 dev ${NAME}t_${NAME}n
	ip netns exec ${NAME}t ip link set ${NAME}t_${NAME}n up
	ip netns exec ${NAME}t ip route add ${NAT_ADDR}/32 via 10.0.0.2

	ip netns exec ${NAME}t ip address add 2001:db8::${NAME}/64 dev ${NAME}t_br0
	ip netns exec ${NAME}t ip link set ${NAME}t_br0 up
	ip netns exec ${NAME}t ip route add 64:ff9b::/96 via 2001:db8::1

	ip netns exec ${NAME}n /sbin/sysctl -w net.ipv4.conf.all.forwarding=1
	ip netns exec ${NAME}n /sbin/sysctl -w net.ipv6.conf.all.forwarding=1
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

setup_ce_xlat ce11 $CE11_ADDR4
add_route_ce12 ce11t
add_route_ce21 ce11t

setup_ce_xlat ce12 $CE12_ADDR4
add_route_ce11 ce12t
add_route_ce21 ce12t

setup_ce_xlat ce21 $CE21_ADDR4
add_route_ce11 ce21t
add_route_ce12 ce21t

# BR addresses and routes

ip netns exec br ip address add 2001:db8::1/64 dev br_br0
ip netns exec br ip address add 203.0.113.1/24 dev br_r4

ip netns exec br ip link set br_br0 up
ip netns exec br ip link set br_r4 up

add_route_ce11 br
add_route_ce12 br
add_route_ce21 br

ip netns exec br /sbin/sysctl -w net.ipv4.conf.all.forwarding=1
ip netns exec br /sbin/sysctl -w net.ipv6.conf.all.forwarding=1

# Random IPv4 Internet node addresses and routes

ip netns exec r4 ip address add 203.0.113.4/24 dev r4_br
ip netns exec r4 ip link set r4_br up
ip netns exec r4 ip route add 192.0.2.0/28 via 203.0.113.1
ip netns exec r4 ip route add 198.51.100.0/28 via 203.0.113.1

# Test all neighbors

sleep 4

test_network() {
	ip netns exec $1 ping -c1 $2
}

test_network c111  $CE11_ADDRL
test_network c112  $CE11_ADDRL
test_network c121  $CE12_ADDRL
test_network c211  $CE21_ADDRL
test_network ce11n 10.0.0.1
test_network ce12n 10.0.0.1
test_network ce21n 10.0.0.1
test_network br    2001:db8::ce11
test_network br    2001:db8::ce12
test_network br    2001:db8::ce21
test_network ce11t 2001:db8::ce12
test_network ce11t 2001:db8::ce21
test_network ce12t 2001:db8::ce21
test_network br    203.0.113.4

# Jool

modprobe jool_mapt

DMR=64:ff9b::/96

add_ce_translator() {
	CE=$1
	EUIP=$2
	BMR6=$3
	BMR4=$4
	EABL=$5

	ip netns exec $CE jool_mapt instance add "$CE" --iptables \
			--end-user-ipv6-prefix $EUIP \
			--bmr.ipv6-prefix $BMR6 \
			--bmr.ipv4-prefix $BMR4 \
			--bmr.ea-bits-length $EABL \
			--dmr $DMR
	ip netns exec $CE ip6tables -t mangle -A PREROUTING -d $EUIP           -j JOOL_MAPT --instance "$CE"
	ip netns exec $CE iptables  -t mangle -A PREROUTING -d 192.0.2.0/24    -j JOOL_MAPT --instance "$CE"
	ip netns exec $CE iptables  -t mangle -A PREROUTING -d 198.51.100.0/24 -j JOOL_MAPT --instance "$CE"
	ip netns exec $CE iptables  -t mangle -A PREROUTING -d 203.0.113.0/24  -j JOOL_MAPT --instance "$CE"
}

add_ce_translator ce11t $CE11_EUIP $MD1_BMR
add_ce_translator ce12t $CE12_EUIP $MD1_BMR
add_ce_translator ce21t $CE21_EUIP $MD2_BMR

ip netns exec br jool_mapt instance add "br" --iptables --dmr $DMR
ip netns exec br jool_mapt -i "br" fmr add $MD1_BMR
ip netns exec br jool_mapt -i "br" fmr add $MD2_BMR

ip netns exec br ip6tables -t mangle -A PREROUTING -d $DMR            -j JOOL_MAPT --instance "br"
ip netns exec br iptables  -t mangle -A PREROUTING -d 192.0.2.0/24    -j JOOL_MAPT --instance "br"
ip netns exec br iptables  -t mangle -A PREROUTING -d 198.51.100.0/24 -j JOOL_MAPT --instance "br"

# NAT

add_nat() {
	NAME=$1
	TO_SOURCE=$2
	ip netns exec ${NAME}n iptables -t nat -A POSTROUTING -o ${NAME}n_${NAME}t \
			-j SNAT --to-source $TO_SOURCE
	ip netns exec ${NAME}n iptables -t nat -A PREROUTING  -i ${NAME}n_${NAME}t \
			-p tcp --dport 2048 -j DNAT --to 192.168.0.2:2048
	ip netns exec ${NAME}n iptables -t nat -A PREROUTING  -i ${NAME}n_${NAME}t \
			-p tcp --dport 2049 -j DNAT --to 192.168.0.3:2049
}

add_nat ce11 192.0.2.1
add_nat ce12 192.0.2.2
add_nat ce21 198.51.100.1

# Graybox

insmod ../../../mod/graybox.ko

