#!/bin/bash

if [[ $UID != 0 ]]; then
	echo "Please start the script as root or sudo."
	exit 1
fi

modprobe -r jool
modprobe -r jool_siit

function start() {
		clear
		echo "$1"
}

function pause() {
	read -p "Press enter to continue"
}

# --------------
# -- Globals ---
# --------------

modprobe jool
jool instance add --iptables -6 64::/96

start "Globals normal display"
( set -x; jool global display )
pause

start "CSV, manually enabled is now false"
( set -x; jool global update manually-enabled false; jool global display --csv )
pause

start "TOS is now 32, no headers"
( set -x; jool global update tos 32; jool global display --csv --no-headers )
pause

start "Other types changed"
( set -x;
	jool global update mtu-plateaus 1,2,3
	jool global update udp-timeout 1:00:00
	jool global update f-args 2
	jool global display
)
pause

start "Error: pool6 edit attempt"
( set -x; jool global update pool6 32::/96 )
pause

modprobe -r jool

# --------------
# --- Footer ---
# --------------

clear
echo "Done."
echo "Missing tests:"
echo "- sudoless request"
echo "- request from differently-versioned client"
