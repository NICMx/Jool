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
# -- instance --
# --------------

function single_module_instance_test() {
	THIS=$1
	OTHER=$2

	start "Error: Module not modprobed"
	( set -x; modprobe $THIS; $OTHER instance display )
	pause

	start "Empty table"
	( set -x; $THIS instance display; )
	pause

	start "'Running', followed by single entry table"
	( set -x
		$THIS instance add --netfilter -6 64::/96 nat64-1
		$THIS -i nat64-1 instance status
		$THIS instance display
	)
	pause
	
	start "Error: Too many Netfilter instances"
	( set -x; $THIS instance add --netfilter -6 128::/96 dummy )
	pause

	start "Error: Duplicate instance name"
	( set -x; $THIS instance add --iptables -6 128::/96 nat64-1 )
	pause

	start "2-entry table (CSV format)"
	( set -x
		$THIS instance add --iptables -6 32::/96 nat64-2
		$THIS instance display --csv
	)
	pause

	start "3-entry table (No headers)"
	( set -x
		$THIS instance add --iptables -6 16::/96 nat64-3
		$THIS instance display --no-headers
	)
	pause

	start "table with 1 and 3 (CSV no headers)"
	( set -x
		$THIS instance remove nat64-2
		$THIS instance display --csv --no-headers
	)
	pause

	start "Empty table"
	( set -x; $THIS instance flush; $THIS instance display )
	pause

	modprobe -r $THIS
}

single_module_instance_test jool jool_siit
single_module_instance_test jool_siit jool

# --------------

function add_dummy_entries() {
	jool instance add --netfilter -6 64::/96 nat64-1
	jool instance add --iptables -6 64::/96 nat64-2
	jool instance add --iptables -6 64::/96 nat64-3
	jool_siit instance add --netfilter -6 64::/96 nat64-1
	jool_siit instance add --iptables -6 64::/96 nat64-2
	jool_siit instance add --iptables -6 64::/96 nat64-3
}

start  "Test instance database management: Remove entries before r-modprobing"
( set -x
	modprobe jool
	modprobe jool_siit
	add_dummy_entries
	jool instance flush
	jool_siit instance flush
	modprobe -r jool
	modprobe -r jool_siit
)
pause

start "This time, r-modprobe with populated database"
( set -x
	modprobe jool
	modprobe jool_siit
	add_dummy_entries
	modprobe -r jool
	modprobe -r jool_siit
)
pause

# -------------
# --- Stats ---
# -------------

modprobe jool
jool instance add --iptables -6 64::/96
jool pool4 add --tcp 192.0.2.99 200-300
jool bib add --tcp 192.0.2.99#250 2001:db8::15#250

start "Stats: Normal"
( set -x; jool stats display )
pause

start "Stats: all"
( set -x; jool stats display --all )
pause

start "Stats: CSV"
( set -x; jool stats display --csv )
pause

start "Stats: Explain"
( set -x; jool stats display --csv --no-headers )
pause

start "Stats: No headers"
( set -x; jool stats display --explain )
pause

# --------------
# --- Global ---
# --------------

modprobe jool
jool instance add --iptables -6 64::/96

start "Globals normal display"
( set -x; jool global display )
pause

start "Tweak Boolean, CSV"
( set -x; jool global update manually-enabled false; jool global display --csv )
pause

start "Tweak Integer, no headers"
( set -x; jool global update tos 32; jool global display --csv --no-headers )
pause

start "Other types changed"
( set -x
	jool global update mtu-plateaus 1,2,3
	jool global update udp-timeout 1:00:00
	jool global update f-args 2
	jool global display
)
pause

start "Error: pool6 edit attempt"
( set -x; jool global update pool6 32::/96 )
pause

# TODO jool_siit needs to validate update --force

modprobe -r jool

# -------------
# --- pool4 ---
# -------------

modprobe jool
jool instance add --iptables -6 64::/96

# TODO missing --csv --no-headers
function display_pool4() {
	jool pool4 display
	jool pool4 display --udp --csv
	jool pool4 display --icmp --no-headers
}

start "Empty TCP pool4"
( set -x; display_pool4 )
pause

start "Add entries"
( set -x
	jool pool4 add --tcp 0.0.0.1 100-300
	jool pool4 add --tcp 0.0.0.2 100-300
	display_pool4
)
pause

start "Add same entries; no changes"
( set -x
	jool pool4 add --tcp 0.0.0.1 100-300
	jool pool4 add --tcp 0.0.0.2 100-300
	display_pool4
)
pause

start "Merge entry, add more entries"
( set -x
	jool pool4 add --tcp  0.0.0.2 200-400
	jool pool4 add --tcp  0.0.0.2 200-400 --mark 100
	jool pool4 add --udp  0.0.0.3 500-600
	jool pool4 add --icmp 0.0.0.3 500-600
	display_pool4
)
pause

# TODO more add merges?

start "Change some max iterations"
( set -x
	jool pool4 add --tcp  --max-iterations 5        0.0.0.1 100-300
	jool pool4 add --udp  --max-iterations auto     0.0.0.3 500-600
	jool pool4 add --icmp --max-iterations infinity 0.0.0.3 500-600
	display_pool4
)
pause

start "Remove some addresses"
( set -x
	jool pool4 remove 0.0.0.1
	display_pool4
)
pause

# TODO Punch holes and stuff?
# TODO --quick

start "Flush the pool"
( set -x; jool pool4 flush; display_pool4 )
pause

start "Error: Too many addresses"
( set -x; jool pool4 add --tcp 192.0.2.0/23 100-200; display_pool4 )
pause

start "Force lots of addresses"
( set -x; jool pool4 add --tcp --force 192.0.2.0/23 100-200; display_pool4 )
pause

modprobe -r jool

# TODO Incorrectly-formed addresses and stuff

# -------------
# ---- BIB ----
# -------------

function display_bib() {
	jool bib display --numeric
	jool bib display --numeric --udp  --csv
	jool bib display --numeric --icmp --csv --no-headers
}

modprobe jool
jool instance add --iptables -6 64::/96

start "Display"
( set -x; display_bib )
pause

start "Add failure: addr4 not in pool4"
( set -x; jool bib add 2001:db8::1#1234 192.0.2.1#1234 )
pause

start "Add success"
( set -x
	jool pool4 add 192.0.2.1 1000-2000 --tcp
	jool pool4 add 192.0.2.1 1000-2000 --udp
	jool pool4 add 192.0.2.1 1000-2000 --icmp
	jool bib add 2001:db8::1#1234 192.0.2.1#1234
	jool bib add 2001:db8::1#1235 192.0.2.1#1235 --tcp
	jool bib add 2001:db8::1#1234 192.0.2.1#1234 --udp
	jool bib add 2001:db8::1#1234 192.0.2.1#1234 --icmp
	display_bib
)
pause

start "Error: IPv4 already exists"
( set -x
	jool bib add 2001:db8::1#1234 192.0.2.1#1236
	jool bib add 2001:db8::1#1236 192.0.2.1#1234
	jool bib add 2001:db8::1#1234 192.0.2.1#1234
)
pause

start "Remove error: Entry does not exist"
( set -x
	jool bib remove 2001:db8::2#1234 192.0.2.2#1234
	jool bib remove 2001:db8::2#1235
	jool bib remove 192.0.2.2#1234
)
pause

start "Remove success"
( set -x
	jool bib remove 2001:db8::1#1234 192.0.2.1#1234
	jool bib remove 2001:db8::1#1235 192.0.2.1#1235 --tcp
	jool bib remove 2001:db8::1#1234 --udp
	jool bib remove 192.0.2.1#1234 --icmp
	display_bib
)
pause

modprobe -r jool

# --------------
# ---- File ----
# --------------

JSON=/tmp/jool-test.conf

function create_valid_file() {
	echo "{
		\"framework\": \"$1\",
		\"instance\": \"$2\",
		\"global\": { \"pool6\": \"$3::/96\" }
	}" > $JSON
}

function add_many_instances() {
	jool instance add --iptables --pool6 64::/96 client-1
	create_valid_file iptables file-1 64
	jool file handle $JSON
	jool instance add --iptables --pool6 64::/96 client-2
	create_valid_file iptables file-2 64
	jool file handle $JSON
	jool instance add --iptables --pool6 64::/96 client-3
	create_valid_file iptables file-3 64
	jool file handle $JSON
	jool instance add --iptables --pool6 64::/96 client-4
	jool instance display
}

modprobe jool

start "Empty file"
( set -x
	echo '{}' > $JSON
	jool file handle $JSON
)
pause

start "Framework included"
( set -x
	echo '{ "framework": "iptables" }' > $JSON
	jool file handle $JSON
)
pause

start "instance included"
( set -x
	echo '{ "framework": "iptables", "instance": "file" }' > $JSON
	jool file handle $JSON
)
pause

start "pool6 included"
( set -x
	create_valid_file iptables file 64
	jool file handle $JSON
)
pause

start "Illegal changes"
( set -x
	create_valid_file netfilter file 64
	jool file handle $JSON
	create_valid_file iptables file 32
	jool file handle $JSON
)
pause

# TODO missing a legal changes test

start "Modify file instance via client"
( set -x
	jool -i file pool4 add 192.0.2.1 100-200 --tcp
	jool -i file pool4 display
)
pause

start "Modify client instance via file"
( set -x
	jool instance add --iptables -6 64::/96 client
	echo '{
		"framework": "iptables",
		"instance": "client",
		"global": {
			"pool6": "64::/96",
			"tos": 123
		}
	}' > $JSON
	jool file handle $JSON
	jool -i client global display
)
pause

start "Remove file instance via client"
( set -x; jool instance remove file; jool instance display )
pause

start "Remove client instance via file"
( set -x; jool -f $JSON instance remove; jool instance display )
pause

start "Add many instances, flush"
( set -x
	add_many_instances
	jool instance flush
	jool instance display
)
pause

start "Add many instances, modprobe -r"
( set -x
	add_many_instances
	modprobe -r jool
)
pause

# --------------
# --- Footer ---
# --------------

# TODO instance test with different namespaces

clear
echo "Done."
echo "Missing tests:"
echo "- sudoless request"
echo "- request from differently-versioned client"
