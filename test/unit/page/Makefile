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


EXTRA_CFLAGS += -DSIIT

PAGE = page

obj-m += $(PAGE).o

$(PAGE)-objs += $(MIN_REQS)
$(PAGE)-objs += ../impersonator/icmp_wrapper.o
$(PAGE)-objs += ../impersonator/nf_hook.o
$(PAGE)-objs += ../impersonator/route.o
$(PAGE)-objs += ../framework/skb_generator.o
$(PAGE)-objs += ../framework/types.o

$(PAGE)-objs += ../../../src/common/netlink/config.o
$(PAGE)-objs += ../../../src/mod/common/config.o
$(PAGE)-objs += ../../../src/mod/common/ipv6_hdr_iterator.o
$(PAGE)-objs += ../../../src/mod/common/packet.o
$(PAGE)-objs += ../../../src/mod/common/rfc6052.o
$(PAGE)-objs += ../../../src/mod/common/rtrie.o
$(PAGE)-objs += ../../../src/mod/common/translation_state.o
$(PAGE)-objs += ../../../src/mod/common/xlator.o
$(PAGE)-objs += ../../../src/mod/siit/defrag.o
$(PAGE)-objs += ../../../src/mod/siit/blacklist4.o
$(PAGE)-objs += ../../../src/mod/siit/eam.o
$(PAGE)-objs += ../../../src/mod/siit/impersonator.o
$(PAGE)-objs += ../../../src/mod/siit/pool.o
$(PAGE)-objs += ../../../src/mod/siit/rfc6791v4.o
$(PAGE)-objs += ../../../src/mod/siit/rfc6791v6.o

$(PAGE)-objs += ../../../src/mod/siit/handling_hairpinning.o
$(PAGE)-objs += ../../../src/mod/common/rfc6145/4to6.o
$(PAGE)-objs += ../../../src/mod/common/rfc6145/6to4.o
$(PAGE)-objs += ../../../src/mod/common/rfc6145/common.o
$(PAGE)-objs += ../../../src/mod/common/rfc6145/core.o
$(PAGE)-objs += ../../../src/mod/common/core.o

$(PAGE)-objs += impersonator.o
$(PAGE)-objs += page_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	-sudo insmod $(PAGE).ko && sudo rmmod $(PAGE)
	sudo dmesg -tc | less
