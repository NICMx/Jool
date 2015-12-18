#!/bin/bash

# Load environment configuration
source environment.sh

POSTFIX=`date +%F_%T`
OUTPUT="$LOGS_DIR/`basename $0`_$POSTFIX.log"

# Clear the system messages 
sudo dmesg -c > /dev/null

TEST_FAIL=0
TEST_PASS=0
TEST_COUNT=0

# Load testing code
source library.sh


### NAT64 not running
nat64_mod_remove 		# Remove module
SECTION="--bib"
OPTS=""
VALUES=( '' )
RETURNS=( ERR1000 )
KERNMSG=( NOERR )
test_options


### Reject empty MTU lists
start_test
SECTION="--translate"
OPTS="--plateaus="
VALUES=( '' )
RETURNS=( ERR1009 )
KERNMSG=( NOERR )
test_options


### Reject zeros in MTU values
start_test
SECTION="--translate"
OPTS="--plateaus"
VALUES=( '0' )
RETURNS=( ERR1000 )
KERNMSG=( ERR1002 )
test_options


### Remove unexistent pool4 address
start_test
SECTION="--pool4"
OPTS="--remove --addr"
VALUES=( '4.4.4.4' )
RETURNS=( ERR1000 )
KERNMSG=( ERR1021 )
test_options


### Remove unexistent pool6 prefix
start_test
SECTION="--pool6"
OPTS="--remove --prefix" 
VALUES=( '4::/40' )
RETURNS=( ERR1000 )
KERNMSG=( ERR1020 )
test_options


### Remove unexistent session by IPv6
start_test
SECTION="--session"
OPTS="--remove --remote6=3::#3 --local6" 
VALUES=( '56::#56' )
RETURNS=( ERR1000 )
KERNMSG=( ERR2500 )
test_options


### Remove unexistent session by IPv4
start_test
SECTION="--session"
OPTS="--remove --remote4=8.8.8.8#3 --local4" 
VALUES=( '9.9.9.9#56' )
RETURNS=( ERR1000 )
KERNMSG=( ERR2500 )
test_options


### Notice of no IPv6 prefix set.
start_test
POOL6_PREF=`$COMMAND "--pool6" | head -1` # Get configured prefix
SECTION="--pool6"
OPTS="--remove --prefix" 
VALUES=( "$POOL6_PREF" )
RETURNS=( success )
KERNMSG=( NOERR )
test_options			# Remove it
let TEST_COUNT++
echo -n "${txtblu}Test($TEST_COUNT):${txtrst} Check prefix is unset: " | tee -a $OUTPUT
if [[ ! "`$COMMAND '--pool6'`" =~ "(empty)" ]]   # Check prefix is unset
then
    echo "${bldred}Failed.${txtrst} Pool6 prefix is still configured." | tee -a $OUTPUT
    let TEST_FAIL++
else
	echo "${bldgre}Ok.${txtrst}" | tee -a $OUTPUT
    let TEST_PASS++
fi
let TEST_COUNT++
echo -n "${txtblu}Test($TEST_COUNT):${txtrst} Ping IPv6 router: " | tee -a $OUTPUT
KERNMSG=( ERR2200 )
LOG=`ping6 -c 1 $IPV6_ROUTER`	# Ping IPv6 router
LOG=`sudo dmesg -c`		# Check we have the expected outcome.
if [ "`echo $LOG | grep -c ${KERNMSG[0]}`" -eq "0" ]
then
    echo "${bldred}Failed.${txtrst} Oh, Schnapps!, we didn't get the expected result(${KERNMSG[0]})." | tee -a $OUTPUT
    let TEST_FAIL++
else
	echo "${bldgre}Ok.${txtrst}" | tee -a $OUTPUT
    let TEST_PASS++
fi
echo "$LOG" >> $OUTPUT


### Notice of no IPv4 pool set.
start_test
POOL4=( `$COMMAND "--pool4" | sed '/Fetched/ d'` )	# Get configured pool addresses
SECTION="--pool4"
OPTS="--remove --address" 
VALUES=( ${POOL4[@]} )
RETURNS=( success success success success )
KERNMSG=( NOERR NOERR NOERR NOERR )
test_options			# Remove it
let TEST_COUNT++
echo -n "${txtblu}Test($TEST_COUNT):${txtrst} Check pool4 is unset: " | tee -a $OUTPUT
if [[ ! "`$COMMAND '--pool4'`" =~ "(empty)" ]]   # Check pool4 is unset
then
    echo "${bldred}Failed.${txtrst} Pool4 is still configured." | tee -a $OUTPUT
    let TEST_FAIL++
else
	echo "${bldgre}Ok.${txtrst}" | tee -a $OUTPUT
    let TEST_PASS++
fi
let TEST_COUNT++
echo -n "${txtblu}Test($TEST_COUNT):${txtrst} Ping IPv4 gateway: " | tee -a $OUTPUT
KERNMSG=( ERR2300 )
LOG=`ping6 -c 1 $IPV4_ROUTER`	# Ping IPv4 gateway
LOG=`sudo dmesg -c`		# Check we have the expected outcome.
if [ "`echo $LOG | grep -c ${KERNMSG[0]}`" -eq "0" ]
then
    echo "${bldred}Failed.${txtrst} Oh, Schnapps!, we didn't get the expected result." | tee -a $OUTPUT
    let TEST_FAIL++
else
	echo "${bldgre}Ok.${txtrst}" | tee -a $OUTPUT
    let TEST_PASS++
fi
echo "$LOG" >> $OUTPUT


### Send a packet to a non-routable address.
start_test
let TEST_COUNT++
echo -n "${txtblu}Test($TEST_COUNT):${txtrst} Ping IPv4 non-existent address: " | tee -a $OUTPUT
LOG=`ping6 -c 1 64:ff9b::192.168.99.99`   # Ping IPv4 non-existent address
#~ LOG=`sudo dmesg -c`		    # Check we have the expected outcome.
RECV=`echo "$LOG" | sed -n -e '/transmitted/{ s/.*transmitted,//; s/received,.*//; s/[ ]*//g; p; }'`
if [ ! "$RECV" -eq "0" ]
then
    echo "${bldred}Failed.${txtrst} Oh, Schnapps!, we didn't get the expected result." | tee -a $OUTPUT
    let TEST_FAIL++
else
	echo "${bldgre}Ok.${txtrst}" | tee -a $OUTPUT
    let TEST_PASS++
fi
echo "$LOG" >> $OUTPUT


### Add an existent pool4 address.
start_test
SECTION="--pool4"
OPTS="--add --addr"
VALUES=( '4.4.4.4' '4.4.4.4' )
RETURNS=( success ERR1000 )
KERNMSG=( NOERR ERR1022 )
test_options


### Turn to static a dynamic session.
start_test
# Create a dynamic session
LOG=`ping6 -c 1 $IPV4_ROUTER`
# Identify the created session
SESSION=`../NAT64/usr/nat64 --session | grep -A 1 -B 1 ${IPV4_ROUTER##*:}`
REMOTE6="`echo $SESSION | sed -n -e 's/.*Remote:[ ]*\([0-9#.]\+\)[ ]\+\([a-fA-F0-9#.:]\+\).\+/\2/ p'`"
LOCAL6="`echo $SESSION | sed -n -e 's/.*Local:[ ]*\([0-9#.]\+\)[ ]\+\([a-fA-F0-9#.:]\+\).\+/\2/ p'`"
LOCAL4="`echo $SESSION | sed -n -e 's/.*Local:[ ]*\([0-9#.]\+\)[ ]\+\([a-fA-F0-9#.:]\+\).\+/\1/ p'`"
REMOTE4="`echo $SESSION | sed -n -e 's/.*Remote:[ ]*\([0-9#.]\+\)[ ]\+\([a-fA-F0-9#.:]\+\).\+/\1/ p'`"
# Convert dynamic session to static
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( ERR1025 ) # Errata: ICMP session was not created due that it already exist, but TCP & UDP were. 
test_options


### Prevent the creation of preexistent static sessions.
start_test
REMOTE6="1::1#1"				# Insert first session
LOCAL6="2::2#2"
LOCAL4="1.1.1.1#1"
REMOTE4="2.2.2.2#2"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( NOERR )
test_options
REMOTE6="3::3#3"				# Insert second session
LOCAL6="4::4#4"
LOCAL4="3.3.3.3#3"
REMOTE4="4.4.4.4#4"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( NOERR )
test_options
REMOTE6="1::1#1"				# Insert third session
LOCAL6="2::2#2"
LOCAL4="3.3.3.3#3"
REMOTE4="4.4.4.4#4"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( ERR1000 )
KERNMSG=( ERR1026 )
test_options


### Reject previously used IPv4 transport address when creating a static sessions.
start_test
REMOTE6="1::1#1"				# Insert first session
LOCAL6="2::2#2"
LOCAL4="1.1.1.1#1"
REMOTE4="2.2.2.2#2"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( NOERR )
test_options
REMOTE6="7::7#7"				# Insert second session
LOCAL6="8::8#8"
LOCAL4="1.1.1.1#1"
REMOTE4="2.2.2.2#2"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( ERR1000 )
KERNMSG=( ERR1025 )
test_options


### Reject use of previously mapped IPv6 remote transport address when creating a static sessions.
start_test
REMOTE6="1::1#1"				# Insert first session
LOCAL6="2::2#2"
LOCAL4="1.1.1.1#1"
REMOTE4="2.2.2.2#2"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( NOERR )
test_options
REMOTE6="1::1#1"				# Insert second session
LOCAL6="6::6#6"
LOCAL4="5.5.5.5#5"
REMOTE4="8.8.8.8#8"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( ERR1000 )
KERNMSG=( ERR1027 )
test_options


### Verify use of previously mapped IPv4 local transport address when creating a static sessions.
start_test
REMOTE6="1::1#1"				# Insert first session
LOCAL6="2::2#2"
LOCAL4="1.1.1.1#1"
REMOTE4="2.2.2.2#2"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( NOERR )
test_options
REMOTE6="1::1#1"				# Insert second session
LOCAL6="6::6#6"
LOCAL4="1.1.1.1#1"
REMOTE4="8.8.8.8#8"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( NOERR )
test_options

### Deny creation of static session when using same IPv4 local transport address but different remote IPv6.
start_test
REMOTE6="1::1#1"				# Insert first session
LOCAL6="2::2#2"
LOCAL4="1.1.1.1#1"
REMOTE4="2.2.2.2#2"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( successfully )
KERNMSG=( NOERR )
test_options
REMOTE6="3::3#3"				# Insert second session
LOCAL6="6::6#6"
LOCAL4="1.1.1.1#1"
REMOTE4="8.8.8.8#8"
SECTION="--session"
OPTS="--add --remote6=$REMOTE6 --local6=$LOCAL6 --local4=$LOCAL4 --remote4"
VALUES=( $REMOTE4 )
RETURNS=( ERR1000 )
KERNMSG=( ERR1028 )
test_options

nat64_mod_remove

print_resume
