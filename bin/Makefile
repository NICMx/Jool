MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -I$(src)/../include

#obj-m += hash_table.o
#hash_table-objs += ../mod/nf_nat64_types.o
#hash_table-objs += ../testing/nf_nat64_hash_table_test.o

obj-m += bs.o
bs-objs := ../mod/nf_nat64_types.o
bs-objs += ../mod/nf_nat64_bib.o
bs-objs += ../mod/nf_nat64_session.o
bs-objs += ../testing/nf_nat64_bib_session_test.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
