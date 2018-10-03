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

$(PAGE)-objs += ../../../common/netlink/config.o
$(PAGE)-objs += ../../../mod/common/config.o
$(PAGE)-objs += ../../../mod/common/ipv6_hdr_iterator.o
$(PAGE)-objs += ../../../mod/common/packet.o
$(PAGE)-objs += ../../../mod/common/pool6.o
$(PAGE)-objs += ../../../mod/common/rfc6052.o
$(PAGE)-objs += ../../../mod/common/rtrie.o
$(PAGE)-objs += ../../../mod/common/translation_state.o
$(PAGE)-objs += ../../../mod/common/xlator.o
$(PAGE)-objs += ../../../mod/stateless/blacklist4.o
$(PAGE)-objs += ../../../mod/stateless/eam.o
$(PAGE)-objs += ../../../mod/stateless/impersonator.o
$(PAGE)-objs += ../../../mod/stateless/pool.o
$(PAGE)-objs += ../../../mod/stateless/rfc6791.o
$(PAGE)-objs += ../../../mod/stateless/rfc6791v6.o

$(PAGE)-objs += ../../../mod/stateless/handling_hairpinning.o
$(PAGE)-objs += ../../../mod/common/rfc6145/4to6.o
$(PAGE)-objs += ../../../mod/common/rfc6145/6to4.o
$(PAGE)-objs += ../../../mod/common/rfc6145/common.o
$(PAGE)-objs += ../../../mod/common/rfc6145/core.o
$(PAGE)-objs += ../../../mod/common/core.o

$(PAGE)-objs += impersonator.o
$(PAGE)-objs += page_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(PAGE).ko && sudo rmmod $(PAGE)
	sudo dmesg -tc | less
