#!/bin/bash

# Tests compilation of Jool in every released kernel version.
#
# 1. Clones Linux (using git), if needed.
# 2. For every Linux version:
#    a. `make modules_prepare` it. 
#    b. Compiles Jool using the prepared kernel.
#
# This script has the following arguments:
# $1. Directory where Linux will be (or has been) cloned.
#     (Will assume the name of the clone is "linux"; ie. "$1/linux".)
# $2. Clone URL of Linux.
#     (Defaults to https://github.com/torvalds/linux.git)
# $3. Source of the kernel module to be compiled.
#     (Defaults to ../../mod)
#
# Author: cdeleon - Nic Mx


function die {
	echo "$1" 1>&2
	exit 1
}

function clean_workspace {
	cd $JOOL_DIR
	make clean > /dev/null 2>&1
	cd $LINUX_DIR
	make clean > /dev/null 2>&1
	rm -f .config
	git clean -xdf > /dev/null 2>&1
}


# Initialize variables.
if [[ -z $1 ]]; then
	GIT_DIR="/home/jool/git"
else
	GIT_DIR="$1"
fi
if [[ -z $2 ]]; then
	LINUX_GIT="https://github.com/torvalds/linux.git"
else
	LINUX_GIT="$2"
fi
if [[ -z $3 ]]; then
	JOOL_DIR=$(echo ${PWD%/test/compilation_test})/mod
else
	JOOL_DIR="$3"
fi
LINUX_DIR="$GIT_DIR/linux"
JOOL_LOG=$(echo $PWD/jool-compile-log.log)
RESULT_LOG=$(echo $PWD/result-compile-log.log)


# Go to the Linux clone.
if [ ! -d $LINUX_DIR ]; then
	cd $GIT_DIR || die "Error cd'ing to $GIT_DIR."
	git clone $LINUX_GIT || die "Error cloning $LINUX_GIT."
fi
cd $LINUX_DIR || die "Error cd'ing to $LINUX_DIR."

>$JOOL_LOG
>$RESULT_LOG


# Update the Linux clone.
make clean
rm -f .config
git clean -xdf > /dev/null 2>&1
git checkout master || die "Error checking out Linux's master branch."
git pull || die "Error pulling the latest Linux code."


# Build an array containing the names of all the available releases.
kernels=($(git tag|grep -v \-));
echo


echo "Starting..."
for a in ${kernels[@]}; do
	# Jool does not support Linux < 3.0.0, so skip those variants.
	if [[ "$a" == *"v2."* ]]; then
		echo "Version $a is unsupported; skipping..."
		continue
	fi
	
	clean_workspace
	
	# Prepare the new kernel.
	cd $LINUX_DIR

	echo -e "\n*********************Using kernel version '$a'***********************" | tee -a $JOOL_LOG $RESULT_LOG

	echo "Checking out..." | tee -a $RESULT_LOG
	git checkout $a > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		echo "Checkout complete!" | tee -a $RESULT_LOG
	else
		echo "Kernel checkout spew error code $?." | tee -a $JOOL_LOG $RESULT_LOG
		continue
	fi

	echo "Preparing kernel for module compilation..." | tee -a $JOOL_LOG $RESULT_LOG
	yes "" | make oldconfig > /dev/null 2>&1
	make modules_prepare > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		echo "Kernel $a prepared (hopefully)." | tee -a $JOOL_LOG $RESULT_LOG
	else
		echo "Kernel preparation spew error code $?." | tee -a $JOOL_LOG $RESULT_LOG
		continue
	fi

	# Compile Jool.
	cd $JOOL_DIR

	echo -e "\nCompiling the kernel module..." | tee -a $JOOL_LOG $RESULT_LOG
	make KERNEL_DIR="$LINUX_DIR" 2>&1 | tee -a $JOOL_LOG | grep --line-buffered '\<[Ee]rror\>'
	if [ ${PIPESTATUS[0]} -eq 0 ]
	then
		echo "Compilation successful!" | tee -a $RESULT_LOG
	else
		echo "Compilation threw error code $?." | tee -a $RESULT_LOG
		continue
	fi
done

clean_workspace
