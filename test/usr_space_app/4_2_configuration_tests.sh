#!/bin/bash

# Initialize testing framework
source library.sh
sudo modprobe jool disabled
COMMAND=jool


### Pool IPv4
OPTS="--pool4 --add"
VALUES=( 1.1.a.1 1.1.1. 1.1.1.1 )
RETURNS=( ERR1010 ERR1010 success )
test_options

### Pool IPv6
OPTS="--pool6 --add"
VALUES=( 1::#3 1::/3a 1::/1 1::/32 )
RETURNS=( ERR1011 ERR1019 ERR1019 success )
test_options

### BIB add (testing v4)
OPTS="--bib --add 1::1#1"
VALUES=( 1#.1.1.1 9b.a.a.a 1.1.1.1 2.2.2.2#22)
RETURNS=( ERR1010 ERR1010 ERR1012 ERR1017 )
test_options

### BIB add (testing v6)
OPTS="--bib --add 1.1.1.1#1"
VALUES=( kk::#2 2:#2 2::1 2::#2 )
RETURNS=( ERR1011 ERR1011 ERR1013 ERR1017 )
test_options

### BIB add (success?)
OPTS="--bib --add"
VALUES=( "9::#9 2.2.2.2#22" )
RETURNS=( success )
test_options

### Debug:
EXPECTED_OUT=( "ERR1017: Something failed :(" )

### Pool IPv4
OPTS="--pool4 --add"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options 

OPTS="--pool4 --remove"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

### Debug:
EXPECTED_OUT=( "Command received successfully."  )

OPTS="--pool4 --add"
VALUES=( 1.1.1.1 )
RETURNS=( success )
test_options

OPTS="--pool4 --remove"
VALUES=( 1.1.1.1 )
RETURNS=( success )
test_options

### Debug:
EXPECTED_OUT=( "ERR1017: Something failed :(" )

### Pool IPv6
OPTS="--pool6 --add"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

OPTS="--pool6 --remove"
VALUES=( '' )
RETURNS=( ERR1017 )
test_options

### Debug:
EXPECTED_OUT=( "Command received successfully."  )

OPTS="--pool6 --add"
VALUES=( 2::/64 )
RETURNS=( success )
test_options

OPTS="--pool6 --remove"
VALUES=( 2::/64 )
RETURNS=( success )
test_options

### Debug:
EXPECTED_OUT=( "ERR1018: Something failed :(" )

# Test empty call to user space app
OPTS=""
VALUES=( '' )
RETURNS=( ERR1018 )
test_options

### Remove nonexistent pool4 address
OPTS="--pool4 --remove"
VALUES=( '4.4.4.4' )
RETURNS=( ERR1000 )
KERNMSG=( ERR1021 )
test_options

### Remove nonexistent pool6 prefix
OPTS="--pool6 --remove" 
VALUES=( '4::/40' )
RETURNS=( ERR1000 )
KERNMSG=( ERR1020 )
test_options

### Remove nonexistent session by IPv6
OPTS="--bib --remove" 
VALUES=( '3::#3' )
RETURNS=( ERR1000 )
KERNMSG=( ERR2500 )
test_options

### Remove nonexistent session by IPv4
SECTION=""
OPTS="--bib --remove" 
VALUES=( '9.9.9.9#56' )
RETURNS=( ERR1000 )
KERNMSG=( ERR2500 )
test_options

### Add an existent pool4 address.
SECTION="--pool4"
OPTS="--add --addr"
VALUES=( '4.4.4.4' '4.4.4.4' )
RETURNS=( success ERR1000 )
KERNMSG=( NOERR ERR1022 )
test_options


sudo modprobe -r jool
print_summary
