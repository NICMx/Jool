#!/bin/sh

if [ $(id -u) != 0 ]; then
	echo "Sorry; I need more privileges."
	exit 1
fi

if [ -z "$1" ]; then
	echo "I need the path to joolif's source root as argument."
	exit 1
fi


set -x

IFNAME="siit0"
JOOLIF_DIR="$1"

insmod ../../mod/graybox.ko
insmod "$JOOLIF_DIR/mod/joolif.ko"

sysctl -w net.ipv4.conf.all.forwarding=1 > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

ip link add name $IFNAME type siit
ip addr add 2001:db8:1c0:2:21::/40 dev $IFNAME # 192.0.2.33
ip addr add 198.51.100.2/5 dev $IFNAME # 2001:db8:1c6:3364:2::
ip link set $IFNAME up

"$JOOLIF_DIR/usr/joolif" $IFNAME pool6 2001:db8:100::/40
"$JOOLIF_DIR/usr/joolif" $IFNAME pool6791v4 198.51.100.1
"$JOOLIF_DIR/usr/joolif" $IFNAME pool6791v6 2001:db8:1c0:2:1::

# Not sure if this is still relevant
sysctl -w net.ipv6.auto_flowlabels=0 > /dev/null

# Sample pings to yourself through xlator:
#	ping 2001:db8:1c6:3364:2::
#	ping 192.0.2.33
#
# End:
#	./end-jool.sh

