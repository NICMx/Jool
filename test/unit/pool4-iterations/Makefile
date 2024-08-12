MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

UNIT = pool4-iterations

obj-m += $(UNIT).o

$(UNIT)-objs += ../../../src/common/types.o
$(UNIT)-objs += ../../../src/mod/common/types.o
$(UNIT)-objs += ../../../src/mod/common/address.o
$(UNIT)-objs += ../framework/unit_test.o
$(UNIT)-objs += ../../../src/mod/common/rbtree.o
$(UNIT)-objs += ../../../src/mod/nat64/pool4/empty.o
$(UNIT)-objs += ../../../src/mod/nat64/pool4/rfc6056.o
$(UNIT)-objs += ../impersonator/route.o
$(UNIT)-objs += iterations.o

EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING
ccflags-y := -I$(src)/../../../src -I$(src)/..

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;

