ifndef KERNEL_DIR
	KERNEL_DIR := /lib/modules/$(shell uname -r)/build
endif

EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DUNIT_TESTING

ccflags-y := -I$(src)/../../../include
# Some tests benefit from being able to validate inner variables.
# This -I allows them to #include .c's directly so they can see more than just
# the API.
ccflags-y += -I$(src)/../../../mod
ccflags-y += $(JOOL_FLAGS)

MIN_REQS = ../../../mod/common/types.o \
	../../../mod/common/address.o \
	../framework/str_utils.o \
	../framework/unit_test.o \
	../impersonator/stats.o \
	../impersonator/xlat.o
