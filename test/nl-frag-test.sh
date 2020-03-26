#!/bin/bash

# Quick 'n dirty kernel-to-userspace Netlink packet fragmentation test.
# First, go to /src/mod/common/nl/nl_core.c. In the jresponse_init() function,
# change
#	response->skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
# into
#	response->skb = genlmsg_new(32, GFP_KERNEL);
# Then recompile/reinstall jool using `make debug` and run this script.
# All validations are visual; sorry.

sudo modprobe -r jool_siit
sudo modprobe -r jool
sudo modprobe jool_siit

function pause() {
	read -p "Press Enter to continue"
}

function print_table_check() {
	echo -e "\\x1b[36mPlease check $1 entries 1-16:\\x1b[0m"
}

function print_dmesg_check() {
	echo -e "\\x1b[36mPlease check the kernel logs include at least one offset:\\x1b[0m"
}

# ---------------------------------------------------------------

# Instance
clear
for i in {1..16}; do
	sudo jool_siit instance add $i --iptables --pool6 64:ff9b::/96
done
sudo dmesg -C

print_table_check "instance"
sudo jool_siit instance display
print_dmesg_check
dmesg

pause


# Globals
clear
sudo jool_siit instance add --iptables --pool6 64:ff9b::/96
sudo dmesg -C

echo -e "\\x1b[36mPlease check this output makes reasonable sense:\\x1b[0m"
sudo jool_siit global display
print_dmesg_check
dmesg

pause


# EAMT
clear
for i in {1..16}; do
	sudo jool_siit eamt add 192.0.2.$i 2001:db8::$i
done
sudo dmesg -C

print_table_check "eamt"
sudo jool_siit eamt display
print_dmesg_check
dmesg

pause


# blacklist4
clear
for i in {1..16}; do
	sudo jool_siit blacklist4 add 203.0.113.$i
done
sudo dmesg -C

print_table_check "blacklist4"
sudo jool_siit blacklist4 display
print_dmesg_check
dmesg

pause


# ---------------------------------------------------------------

sudo modprobe -r jool_siit
sudo modprobe jool

# ---------------------------------------------------------------

# Instance
clear
for i in {1..16}; do
	sudo jool instance add $i --iptables --pool6 64:ff9b::/96
done
sudo dmesg -C

print_table_check "instance"
sudo jool instance display
print_dmesg_check
dmesg

pause


# Globals
clear
sudo jool instance add --iptables --pool6 64:ff9b::/96
sudo dmesg -C

echo -e "\\x1b[36mPlease check this output makes reasonable sense:\\x1b[0m"
sudo jool global display
print_dmesg_check
dmesg

pause


# pool4
clear
for i in {1..16}; do
	sudo jool pool4 add --tcp 192.0.2.$i 10-20
done
sudo dmesg -C

print_table_check "pool4"
sudo jool pool4 display --tcp
sudo jool pool4 display --udp
sudo jool pool4 display --icmp
print_dmesg_check
dmesg

pause


# BIB
clear
for i in {1..16}; do
	sudo jool bib add --tcp 192.0.2.$i#10 2001:db8::$i#10
done
sudo dmesg -C

print_table_check "bib"
sudo jool bib display --tcp --numeric
sudo jool bib display --udp --numeric
sudo jool bib display --icmp --numeric
print_dmesg_check
dmesg

pause


# Session
clear
echo -e "\\x1b[36mPreparing test namespace. Please wait...\\x1b[0m"

sudo ip netns add joolns
sudo ip link add name to_jool type veth peer name to_world
sudo ip link set up dev to_jool
sudo ip link set dev to_world netns joolns
sudo ip netns exec joolns ip link set up dev to_world

for i in {1..16}; do
	sudo ip addr add 2001:db8::1:$i/96 dev to_jool
done
sudo ip addr add 192.0.2.8/24 dev to_jool
sudo ip netns exec joolns ip addr add 2001:db8::1/96 dev to_world
sudo ip netns exec joolns ip addr add 192.0.2.1/24 dev to_world
sudo ip route add 64:ff9b::/96 via 2001:db8::1

sudo modprobe jool
sudo ip netns exec joolns jool instance add --netfilter --pool6 64:ff9b::/96

# Wait until the namespace is traversable.
ping6 2001:db8::1 -c1 -W60
ping 192.0.2.1 -c1 -W60

# Create the sessions.
for i in {1..16}; do
	ping6 64:ff9b::192.0.2.8 -I 2001:db8::1:$i -c1 > /dev/null
done

sudo dmesg -C

print_table_check "session"
sudo ip netns exec joolns jool session display --tcp --numeric --csv
sudo ip netns exec joolns jool session display --udp --numeric --csv
sudo ip netns exec joolns jool session display --icmp --numeric --csv
print_dmesg_check
dmesg

sudo modprobe -r jool
sudo ip netns del joolns
echo -e "\\x1b[36mTest namespace deleted.\\x1b[0m"
	