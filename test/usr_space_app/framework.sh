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
# For every element in the $VALUES list, runs the following command:
#
#	$COMMAND $OPTS <value>
#
# And ensures the result (error code) and output (standard output and standard
# error) match the expected values in the $RETURNS and $OUTPUTS lists,
# respectively.
###
function test_options() {	
    echo "${undyel}>>> Test group:${txtrst} " "$OPTS"
    echo "${undyel}>>> Test group:${txtrst} " "$OPTS" >> $OUTPUT

    RESULT=""
    ii=0
    while [ "$ii" -lt "${#VALUES[@]}" ]
    do
		TEST_DESC="${txtblu}Test($(($TEST_COUNT+1))):${txtrst} \" $COMMAND $OPTS ${VALUES[$ii]}"
		echo -n "$TEST_DESC"
		TEST_OUTPUT="$(sudo "$COMMAND" $OPTS ${VALUES[$ii]} 2>&1)"
		TEST_ERROR_CODE=$?
		# Most of the time the app returns generic -EINVAL on failure.
		# So we don't really care what the error code is; we only need
		# the status (success/failure).
		# success = 1, failure = 0.
		TEST_ERROR_CODE=$([ $TEST_ERROR_CODE -eq 0 ] && echo "1" || echo "0")

		# echo "Comparing ${TEST_ERROR_CODE} vs ${RETURNS[$ii]}"
		if [[ "${TEST_ERROR_CODE}" -eq "${RETURNS[$ii]}" ]]
		then
			RESULT_CODE="OK"
		else
			RESULT_CODE="FAIL"
		fi

		# echo "Comparing ${TEST_OUTPUT} vs ${OUTPUTS[$ii]}"
		if [[ -z "${OUTPUTS[$ii]}" || "${TEST_OUTPUT}" = *"${OUTPUTS[$ii]}"* ]]
		then
			RESULT_OUTPUT="OK"
		else
			RESULT_OUTPUT="FAIL"
		fi

		[ "$RESULT_CODE" == "OK" ] && [ "$RESULT_OUTPUT" == "OK" ] && RESULT=" \": ${bldgre}Ok.${txtrst}"
		[ "$RESULT_CODE" == "FAIL" ] && RESULT=" \": ${bldred}Failed.${txtrst} Result Code> Expected(${RETURNS[$ii]}) but received(${TEST_ERROR_CODE})"
		[ "$RESULT_OUTPUT" == "FAIL" ] && RESULT+=" \": ${bldred}Failed.${txtrst} Output> Expected(${OUTPUTS[$ii]}) but received(${TEST_OUTPUT})"
		[ "$RESULT_CODE" == "OK" ] && [ "$RESULT_OUTPUT" == "OK" ] && let TEST_PASS++
		[ "$RESULT_CODE" == "FAIL" ] || [ "$RESULT_OUTPUT" == "FAIL" ] && let TEST_FAIL++

		echo "$RESULT"

		# Save test output
		echo -n "$TEST_DESC" >> $OUTPUT
		echo "$RESULT" >> $OUTPUT
		#~ echo "> Test output: ${TEST_ERROR_CODE}" >> $OUTPUT

		let ii++
		let TEST_COUNT++
    done
}

function print_summary() {
	echo "${bldazu}>>> SUMMARY:${txtrst} Total tests=${bldblu}$TEST_COUNT${txtrst} , Test passed=${bldgre}$TEST_PASS${txtrst} , Test failed=${bldred}$TEST_FAIL${txtrst}" | tee -a $OUTPUT	
}


# Initialize the test.
TEST_FAIL=0
TEST_PASS=0
TEST_COUNT=0

mkdir -p logs
OUTPUT="logs/`basename $0`_`date +%F_%T`.log"

sudo dmesg -C
