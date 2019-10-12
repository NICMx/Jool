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


BIBTABLE = bibtable

obj-m += $(BIBTABLE).o

$(BIBTABLE)-objs += $(MIN_REQS)
$(BIBTABLE)-objs += ../../../src/mod/common/global-impl.o
$(BIBTABLE)-objs += ../../../src/mod/common/translation_state.o
$(BIBTABLE)-objs += ../../../src/mod/common/db/config.o
$(BIBTABLE)-objs += ../../../src/mod/common/db/rbtree.o
$(BIBTABLE)-objs += ../../../src/mod/common/db/bib/db.o
$(BIBTABLE)-objs += ../impersonator/icmp_wrapper.o
$(BIBTABLE)-objs += ../impersonator/bib.o
$(BIBTABLE)-objs += ../impersonator/route.o
$(BIBTABLE)-objs += ../impersonator/stats.o
$(BIBTABLE)-objs += ../impersonator/xlator.o
$(BIBTABLE)-objs += bibtable_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	-sudo insmod $(BIBTABLE).ko && sudo rmmod $(BIBTABLE)
	sudo dmesg -tc | less
