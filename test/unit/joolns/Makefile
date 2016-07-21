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
$(JOOLNS)-objs += ../../../mod/common/atomic_config.o
$(JOOLNS)-objs += ../../../mod/common/config.o
$(JOOLNS)-objs += ../../../mod/common/rtrie.o
$(JOOLNS)-objs += ../../../mod/stateless/blacklist4.o
$(JOOLNS)-objs += ../../../mod/stateless/pool.o
$(JOOLNS)-objs += ../../../mod/stateless/rfc6791.o
$(JOOLNS)-objs += ../../../mod/stateless/eam.o
$(JOOLNS)-objs += ../../../mod/stateless/impersonator.o
$(JOOLNS)-objs += ../../../mod/common/xlator.o
$(JOOLNS)-objs += ../impersonator/route.o
$(JOOLNS)-objs += impersonator.o
$(JOOLNS)-objs += joolns_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(JOOLNS).ko && sudo rmmod $(JOOLNS)
	sudo dmesg -c | less
