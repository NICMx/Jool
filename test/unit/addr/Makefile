MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING
EXTRA_CFLAGS += -DBENCHMARK

#CC=cgcc
ccflags-y := -I$(src)/../../include
ccflags-y += -I$(src)/../../mod/common
ccflags-y += -I$(src)/../../mod/stateful
ccflags-y += -I$(src)/../../mod/stateless


ADDR = addr

obj-m += $(ADDR).o

MIN_REQS = ../../mod/common/types.o \
	../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o


$(ADDR)-objs += $(MIN_REQS)
$(ADDR)-objs += address_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
