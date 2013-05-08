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


### Session remote 6
SECTION="--session"
OPTS="--add --remote6"
VALUES=( 2::$2 2::##0 2::#8 )
RETURNS=( ERR1013 ERR1017 ERR1017 )
test_options

### Session local 6
SECTION="--session"
OPTS="--add --local6"
VALUES=( 3::# 3::#++ 3::#6 )
RETURNS=( ERR1013 ERR1007 ERR1017 )
test_options


print_resume
