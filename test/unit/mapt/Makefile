# It appears the -C's during the makes below prevent this include from happening
# when it's supposed to.
# For that reason, I can't just do "include ../common.mk". I need the absolute
# path of the file.
# Unfortunately, while the (as always utterly useless) working directory is (as
# always) brain-dead easy to access, the easiest way I found to get to the
# "current" directory is the mouthful below.
# And yet, it still has at least one major problem: if the path contains
# whitespace, `lastword $(MAKEFILE_LIST)` goes apeshit.
# This is the one and only reason why the unit tests need to be run in a
# space-free directory.
include $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))/../common.mk


KBUILD_EXTRA_SYMBOLS = $(src)/../../../src/mod/common/Module.symvers
UNIT = mapt

obj-m += $(UNIT).o

$(UNIT)-objs += ../framework/skb_generator.o
$(UNIT)-objs += ../framework/unit_test.o
$(UNIT)-objs += mapt_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	sudo modprobe jool_common
	-sudo insmod $(UNIT).ko && sudo rmmod $(UNIT)
	sudo modprobe -r jool_common
	#sudo dmesg -tc | less
	sudo dmesg -tc
