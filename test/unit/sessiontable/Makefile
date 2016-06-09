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


SESSIONTABLE = sessiontable

obj-m += $(SESSIONTABLE).o

$(SESSIONTABLE)-objs += $(MIN_REQS)
$(SESSIONTABLE)-objs += ../../../mod/common/config.o
$(SESSIONTABLE)-objs += ../../../mod/common/rbtree.o
$(SESSIONTABLE)-objs += ../../../mod/stateful/session/entry.o
$(SESSIONTABLE)-objs += ../../../mod/stateful/session/table.o
$(SESSIONTABLE)-objs += ../../../mod/stateful/session/pkt_queue.o
$(SESSIONTABLE)-objs += ../impersonator/bib.o
$(SESSIONTABLE)-objs += ../impersonator/icmp_wrapper.o
$(SESSIONTABLE)-objs += ../impersonator/route.o
$(SESSIONTABLE)-objs += sessiontable_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(SESSIONTABLE).ko && sudo rmmod $(SESSIONTABLE)
	sudo dmesg -c | less
