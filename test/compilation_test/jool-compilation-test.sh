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
#
# Author: cdeleon - Nic Mx


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
JOOL_DIR=$(echo ${PWD%/test/compilation_test})
LINUX_DIR="$GIT_DIR/linux"

JOOL_LOG=$(echo $PWD/jool-compile-log.log)
RESULT_LOG=$(echo $PWD/result-compile-log.log)

# Go to the Linux clone.
if [ ! -d $LINUX_DIR ]; then
	cd $GIT_DIR
	git clone $LINUX_GIT
fi
cd $LINUX_DIR

>$JOOL_LOG
>$RESULT_LOG

# Update the Linux clone.
make clean
rm .config
git clean -xdf
git checkout master
git pull

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

	# Prepare the new kernel.
	cd $LINUX_DIR

	echo -e "\n*********************Using kernel version $a***********************" | tee -a $JOOL_LOG $RESULT_LOG
	echo "Checking out..." | tee -a $RESULT_LOG
	git checkout $a
	echo "Checkout complete!" | tee -a $RESULT_LOG

	echo "Preparing kernel for module compilation..." | tee -a $JOOL_LOG $RESULT_LOG

	yes "" | make oldconfig > /dev/null 2>&1
	make modules_prepare > /dev/null 2>&1

	if [ $? -eq 0 ]
	then
		echo "Kernel $a prepared (hopefully)." | tee -a $JOOL_LOG $RESULT_LOG
	else
		echo "Kernel preparation spew error code $?." | tee -a $JOOL_LOG $RESULT_LOG
	fi

	# Compile Jool.
	cd $JOOL_DIR/mod

	echo -e "\nCompiling Jool using kernel $a..." | tee -a $JOOL_LOG $RESULT_LOG
	make KERNEL_DIR="$LINUX_DIR" 2>&1 | tee -a $JOOL_LOG | grep --line-buffered '\<[Ee]rror\>'
	if [ ${PIPESTATUS[0]} -eq 0 ]
	then
		echo "Compilation successful!" | tee -a $RESULT_LOG
	else
		echo "Compilation threw error code $?." | tee -a $RESULT_LOG
	fi

	make clean > /dev/null 2>&1
	cd $LINUX_DIR
	make clean > /dev/null 2>&1
	rm .config
	git clean -xdf
done

