#!/bin/bash

### Text color variables
txtund=$(tput sgr 0 1)          # Underline
txtbld=$(tput bold)             # Bold
txtred=$(tput setaf 1) #  red
txtgre=$(tput setaf 2) #  green
txtyel=$(tput setaf 3) #  yellow
txtblu=$(tput setaf 4) #  blue
txtazu=$(tput setaf 6) #  azure blue
txtwhi=$(tput setaf 7) #  white
#
bldred=${txtbld}${txtred} #  red
bldgre=${txtbld}${txtgre} #  gree
bldyel=${txtbld}${txtyel} #  yellow
bldblu=${txtbld}${txtblu} #  blue
bldazu=${txtbld}${txtazu} #  azure blue
bldwhi=${txtbld}${txtwhi} #  white
#
undyel=${txtund}${txtyel} #  yellow
#
txtrst=$(tput sgr0)             # Reset
info=${bldwht}*${txtrst}        # Feedback
pass=${bldblu}*${txtrst}
warn=${bldred}*${txtrst}
ques=${bldblu}?${txtrst}


###
# Test code parameters
#
# Inputs:
#	COMMAND
#	SECTION
#	OPTS
#	OUTPUT
#	VALUES
#	RETURNS
# Outputs:
#	TEST_COUNT
#	TEST_PASS
#	TEST_FAIL
function test_options(){	
    echo "${undyel}>>> Test group:${txtrst} " "$SECTION" "$OPTS"
    echo "${undyel}>>> Test group:${txtrst} " "$SECTION" "$OPTS" >> $OUTPUT

	ARGS="$1"
    RESULT=""
    DMESG_FULL=""
    ii=0
    while [ "$ii" -lt "${#VALUES[@]}" ]
    do
		if [ "${#VALUES[$ii]}" == 0 ]
		then
			TEST_DESC="${txtblu}Test($(($TEST_COUNT+1))):${txtrst} \" $COMMAND $SECTION $OPTS"
			echo -n "$TEST_DESC"
			TEST_OUT=`"$COMMAND" $SECTION $OPTS` # Un-comment this
		else
			TEST_DESC="${txtblu}Test($(($TEST_COUNT+1))):${txtrst} \" $COMMAND $SECTION $OPTS=${VALUES[$ii]}"
			echo -n "$TEST_DESC"
			TEST_OUT=`"$COMMAND" "$SECTION" $OPTS=${VALUES[$ii]}` # Un-comment this
		fi
	
		DMESG=`sudo dmesg -c`
		DMESG_FULL+="$DMESG"
	
		#TEST_OUT="${EXPECTED_OUT[$ii]}" # Debug

# Know bug: 
# 	Due reg exp comparation between the test output and the
#	expected value, test will be assessed as correct even if 
#	this pair of values are different. 
#	I. E., the output "ERR1017" matches with the expected 
#	value "ERR101".
 
		if [[ "${TEST_OUT}" =~ "${RETURNS[$ii]}" ]] 
		then
			RESULT_TEST="OK"
		else
			RESULT_TEST="FAIL"	
		fi

		if [ "${KERNMSG[$ii]}" == "NOERR" ]
		then
			if [[ "${DMESG}" =~ "ERR" ]] 
			then
				RESULT_DMESG="FAIL"
			else
				RESULT_DMESG="OK"
			fi
		else
			if [[ "${DMESG}" =~ "${KERNMSG[$ii]}" ]] 
			then
				RESULT_DMESG="OK"
			else
				RESULT_DMESG="FAIL"
			fi
		fi

		[ "$RESULT_TEST" == "OK" ] && [ "$RESULT_DMESG" == "OK" ] && RESULT=" \": ${bldgre}Ok.${txtrst}"
		[ "$RESULT_TEST" == "FAIL" ] && RESULT=" \": ${bldred}Failed.${txtrst} Output> Expected(${RETURNS[$ii]}) but received(${TEST_OUT})"
		[ "$RESULT_DMESG" == "FAIL" ] && RESULT+=" \": ${bldred}Failed.${txtrst} Dmesg> Expected(${KERNMSG[$ii]}) but observed something else."
		[ "$RESULT_TEST" == "OK" ] && [ "$RESULT_DMESG" == "OK" ] && let TEST_PASS++
		[ "$RESULT_TEST" == "FAIL" ] || [ "$RESULT_DMESG" == "FAIL" ] && let TEST_FAIL++
		
		echo "$RESULT"
		
		# Save test output
		echo -n "$TEST_DESC" >> $OUTPUT
		echo "$RESULT" >> $OUTPUT
		#~ echo "> Test output: ${TEST_OUT}" >> $OUTPUT

		let ii++
		let TEST_COUNT++
    done

	# Save kernel messages
	echo "> Kernel messages (dmesg):" >> $OUTPUT
	echo "$DMESG_FULL" >> $OUTPUT
	#	echo 	sudo dmesg -c >> $OUTPUT # Debug
	echo ""	>> $OUTPUT

}

###
# Create a clean workspace.
#
function start_test(){
	nat64_mod_remove
	sudo dmesg -c > /dev/null	    # Clear messages 
	nat64_mod_insert				# Insert module
	# Clean variables
	unset REMOTE6
	unset LOCAL6
	unset LOCAL4
	unset REMOTE4
	unset SECTION
	unset OPTS
	unset VALUES
	unset RETURNS
	unset KERNMSG
	unset RESULT
}

###
# Assures that the module is not running.
#
function nat64_mod_remove(){
    if [ "`lsmod | grep nat64`" ]
    then
		pushd $MOD_DIR 	> /dev/null
		make remove		> /dev/null
		popd 			> /dev/null
    #~ else
		#~ echo "NAT64 module wasn't loaded"
    fi
}

###
# Assures that the module is running.
#
function nat64_mod_insert(){
    source environment.sh

    #~ if [ "`lsmod | grep nat64`" ]
    #~ then
		#~ echo "NAT64 module was already loaded"
    #~ else
		nat64_mod_remove	> /dev/null
		pushd $MOD_DIR  	> /dev/null
		make insert			> /dev/null
		popd 				> /dev/null
    #~ fi
}

function print_resume(){
	echo "${bldazu}>>> RESUME:${txtrst} Total tests=${bldblu}$TEST_COUNT${txtrst} , Test passed=${bldgre}$TEST_PASS${txtrst} , Test failed=${bldred}$TEST_FAIL${txtrst}" | tee -a $OUTPUT	
}


