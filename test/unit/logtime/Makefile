MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING
EXTRA_CFLAGS += -DBENCHMARK

#CC=cgcc
ccflags-y := -I$(src)/../../../include
ccflags-y += -I$(src)/../../../mod/common
ccflags-y += -I$(src)/../../../mod/stateful
ccflags-y += -I$(src)/../../../mod/stateless


LOGTIME = logtime

obj-m += $(LOGTIME).o

MIN_REQS = ../../../mod/common/types.o \
	../../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o


$(LOGTIME)-objs += $(MIN_REQS)
$(LOGTIME)-objs += log_time_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  *.ko  *.o
test:
	sudo dmesg -C
	-sudo insmod $(LOGTIME).ko && sudo rmmod $(LOGTIME)
	sudo dmesg -c | less
