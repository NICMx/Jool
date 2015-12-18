#!/bin/bash
# Jool Compile is in charge of compiling jool against all the versions of Linux kernel
# released in the torvalds/linux git repository, in order to give a basic overview of 
# Jool compatibility.
# Author: Cristobal De Leon - Nic Mx

JOOL_DIR="../.."
LINUX_DIR="$1"

# Check if directory exists, if not, create it, then move to the directory and clone linux's git
if [ -d $LINUX_DIR ]; then
	cd $LINUX_DIR
else
	mkdir $LINUX_DIR
	cd $LINUX_DIR
fi

# If any file exists, it will attempt a pull, if not, it will clone
# TODO: need to test this part thoroughly
[ "$(ls -A)" ] && git pull || git clone https://github.com/torvalds/linux.git

KERNELS=($(git tag|grep -v \-))

for a in ${KERNELS[@]}; do
	echo "=============="
	echo "Using Linux $a"
	echo "=============="
	# We don't support 2.x versions, skip them
	if [[ "$a" == *"v2."* ]]; then
		echo "Skipping $a"
		continue
	fi

	mkdir $a
	git --work-tree=$LINUX_GIT/$a checkout $a -- .
	cd $a

	yes ""|make oldconfig >/dev/null 2>&1
	make modules_prepare >/dev/null 2>&1
	if [ $& -eq 0 ]; then
		echo "Kernel $a compiled"
	else
		echo "Kernel $a compilation probably failed"
	fi

	cd $JOOL_DIR/mod

	sed -ri 's;(^KERNEL_DIR :=).*;\1 '"$LINUX_DIR/$a"';' ./stateful/Makefile ./stateless/Makefile

	make 2>&1 | grep --line-buffered '\<[Ee]rror\>'
	if [ ${PIPESTATUS[0]} -eq 0]; then
		echo "Successful compilation!"
	else
		echo "Something went wrong..."
	fi
	cd $LINUX_GIT
	rm -r $a
done
