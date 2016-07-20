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


PALLOC = palloc4

obj-m += $(PALLOC).o

$(PALLOC)-objs += $(MIN_REQS)
$(PALLOC)-objs += ../../../mod/common/config.o
$(PALLOC)-objs += ../../../mod/common/ipv6_hdr_iterator.o
$(PALLOC)-objs += ../../../mod/common/pool6.o
$(PALLOC)-objs += ../../../mod/common/rbtree.o
$(PALLOC)-objs += ../../../mod/common/rfc6052.o
$(PALLOC)-objs += ../../../mod/common/rfc6145/common.o
$(PALLOC)-objs += ../../../mod/common/rfc6145/4to6.o
$(PALLOC)-objs += ../../../mod/common/rfc6145/6to4.o
$(PALLOC)-objs += ../../../mod/stateful/impersonator.o
$(PALLOC)-objs += ../../../mod/stateful/pool4/db.o
$(PALLOC)-objs += ../../../mod/stateful/pool4/empty.o
$(PALLOC)-objs += ../framework/types.o
$(PALLOC)-objs += ../impersonator/icmp_wrapper.o
$(PALLOC)-objs += ../impersonator/route.o
$(PALLOC)-objs += port_allocator_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(PALLOC).ko && sudo rmmod $(PALLOC)
	sudo dmesg -c | less
