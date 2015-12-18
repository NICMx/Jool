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

### Debug:
EXPECTED_OUT=( "ERR1017: Algo fallo :(" )

### Pool IPv4
SECTION="--pool4"
OPTS="--add"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options 

SECTION="--pool4"
OPTS="--remove"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

### Debug:
EXPECTED_OUT=( "Command received successfully."  )

SECTION="--pool4"
OPTS="--add --address"
VALUES=( 1.1.1.1 )
RETURNS=( success )
test_options

SECTION="--pool4"
OPTS="--remove --address"
VALUES=( 1.1.1.1 )
RETURNS=( success )
test_options

### Debug:
EXPECTED_OUT=( "ERR1017: Algo fallo :(" )

### Pool IPv6
SECTION="--pool6"
OPTS="--add"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

SECTION="--pool6"
OPTS="--remove"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

### Debug:
EXPECTED_OUT=( "Command received successfully."  )

SECTION="--pool6"
OPTS="--add --prefix"
VALUES=( 2::/64 )
RETURNS=( success )
test_options

SECTION="--pool6"
OPTS="--remove --prefix"
VALUES=( 2::/64 )
RETURNS=( success )
test_options

### Debug:
EXPECTED_OUT=( "ERR1017: Algo fallo :(" )

### Session
SECTION="--session"
OPTS="--add"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

SECTION="--session"
OPTS="--remove"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

### Debug:
EXPECTED_OUT=( "ERR1018: Algo fallo :(" )

# Test empty call to user space app
SECTION=""
OPTS=""
VALUES=( '' )
RETURNS=( ERR1018 )
test_options

print_resume
