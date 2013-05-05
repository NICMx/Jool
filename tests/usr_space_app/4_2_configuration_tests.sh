#!/bin/bash

# Load environment configuration
source environment.sh

POSTFIX=`date +%F_%T`
OUTPUT="$LOGS_DIR/`basename $0`_$POSTFIX.log" # Un-comment this
#OUTPUT="/dev/null" # Debug

# Clear the system messages 
sudo dmesg -c > /dev/null  # Un-comment this
#echo	sudo dmesg -c > /dev/null # Debug

TEST_FAIL=0
TEST_PASS=0
TEST_COUNT=0

# Load testing code
source library.sh

# Insert module
nat64_mod_remove
nat64_mod_insert


### Pool IPv4
SECTION="--pool4"
OPTS="--add --addr"
VALUES=( 1.1.a.1 1.1.1. 1.1.1.1 )
RETURNS=( ERR1010 ERR1010 success )
test_options


### Pool IPv6
SECTION="--pool6"
OPTS="--add --prefix"
VALUES=( 1::#3 1::/3a 1::/1 1::/32 )
RETURNS=( ERR1011 ERR1019 ERR1019 success )
test_options


### Session local 4
SECTION="--session"
OPTS="--add --local4"
VALUES=( 1#.1.1.1 9b.a.a.a 1.1.1.1 2.2.2.2#22)
RETURNS=( ERR1010 ERR1010 ERR1012 ERR1017 )
test_options


### Session local 6
SECTION="--session"
OPTS="--add --local6"
VALUES=( kk::#2 2:#2 2::1 2::#2 )
RETURNS=( ERR1011 ERR1011 ERR1013 ERR1017 )
test_options

### Session remote 4
SECTION="--session"
OPTS="--add --remote4"
VALUES=( 55.55 0 5.5.5.5 5.5.5.5#6 )
RETURNS=( ERR1010 ERR1010 ERR1012 ERR1017 )
test_options

### Session remote 6
SECTION="--session"
OPTS="--add --remote6"
VALUES=( 8/:#8 m.n::#0 9::1 9::#9 )
RETURNS=( ERR1011 ERR1011 ERR1013 ERR1017 )
test_options


### Add a static session
SECTION="--session"
OPTS="--add --remote6=9::#9 --remote4=5.5.5.5#6 --local6=2::#2 --local4"
VALUES=( 2.2.2.2#22 )
RETURNS=( success )
test_options

print_resume
