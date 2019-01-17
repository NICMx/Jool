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

JOOLNS = joolns

obj-m += $(JOOLNS).o

$(JOOLNS)-objs += $(MIN_REQS)
$(JOOLNS)-objs += ../../../src/common/netlink/config.o
$(JOOLNS)-objs += ../../../src/mod/common/atomic_config.o
$(JOOLNS)-objs += ../../../src/mod/common/common-global.o
$(JOOLNS)-objs += ../../../src/mod/common/config.o
$(JOOLNS)-objs += ../../../src/mod/common/rtrie.o
$(JOOLNS)-objs += ../../../src/mod/common/xlator.o
$(JOOLNS)-objs += ../../../src/mod/siit/defrag.o
$(JOOLNS)-objs += ../../../src/mod/siit/blacklist4.o
$(JOOLNS)-objs += ../../../src/mod/siit/pool.o
$(JOOLNS)-objs += ../../../src/mod/siit/rfc6791v4.o
$(JOOLNS)-objs += ../../../src/mod/siit/eam.o
$(JOOLNS)-objs += ../../../src/mod/siit/impersonator.o
$(JOOLNS)-objs += ../impersonator/nf_hook.o
$(JOOLNS)-objs += ../impersonator/route.o
$(JOOLNS)-objs += impersonator.o
$(JOOLNS)-objs += joolns_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	-sudo insmod $(JOOLNS).ko && sudo rmmod $(JOOLNS)
	sudo dmesg -tc | less
