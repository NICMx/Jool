MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING
EXTRA_CFLAGS += -DBENCHMARK
EXTRA_CFLAGS += -DSIIT

#CC=cgcc
ccflags-y := -I$(src)/../../../include
ccflags-y += -I$(src)/../../../mod/common
ccflags-y += -I$(src)/../../../mod/stateful
ccflags-y += -I$(src)/../../../mod/stateless


JOOLNS = joolns

obj-m += $(JOOLNS).o

MIN_REQS = ../../../mod/common/types.o \
	../../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/error_pool.o \
	../impersonator/stats.o \
	../impersonator/xlat.o


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
$(JOOLNS)-objs += ../impersonator/nl.o
$(JOOLNS)-objs += ../impersonator/route.o
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
