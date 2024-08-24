MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

UNIT = bibtable

obj-m += $(UNIT).o

$(UNIT)-objs += ../../../src/common/types.o
$(UNIT)-objs += ../../../src/mod/common/types.o
$(UNIT)-objs += ../../../src/mod/common/address.o
$(UNIT)-objs += ../framework/unit_test.o
$(UNIT)-objs += ../../../src/mod/common/translation_state.o
$(UNIT)-objs += ../../../src/mod/common/wrapper-config.o
$(UNIT)-objs += ../../../src/mod/common/wrapper-global.o
$(UNIT)-objs += ../../../src/mod/common/db/global.o
$(UNIT)-objs += ../../../src/mod/common/db/rbtree.o
$(UNIT)-objs += ../../../src/mod/common/db/bib/db.o
$(UNIT)-objs += ../../../src/mod/common/nl/attribute.o
$(UNIT)-objs += ../impersonator/bib.o
$(UNIT)-objs += ../impersonator/icmp_wrapper.o
$(UNIT)-objs += ../impersonator/route.o
$(UNIT)-objs += ../impersonator/stats.o
$(UNIT)-objs += ../impersonator/xlator.o
$(UNIT)-objs += bibtable_test.o

EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING
ccflags-y := -I$(src)/../../../src -I$(src)/..

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
test:
	sudo dmesg -C
	-sudo insmod $(UNIT).ko && sudo rmmod $(UNIT)
	sudo dmesg -tc | less
