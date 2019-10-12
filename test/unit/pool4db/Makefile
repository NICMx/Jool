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


POOL4DB = pool4db

obj-m += $(POOL4DB).o

$(POOL4DB)-objs += $(MIN_REQS)
$(POOL4DB)-objs += ../../../src/mod/common/db/rbtree.o
$(POOL4DB)-objs += ../../../src/mod/common/db/pool4/empty.o
$(POOL4DB)-objs += ../impersonator/route.o
$(POOL4DB)-objs += impersonator.o
$(POOL4DB)-objs += pool4db_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	-sudo insmod $(POOL4DB).ko && sudo rmmod $(POOL4DB)
	sudo dmesg -tc | less
