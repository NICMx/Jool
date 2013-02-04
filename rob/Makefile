MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -I$(src)/../include
EXTRA_CFLAGS += -I$(src)/../mod
EXTRA_CFLAGS += -I$(src)/.
EXTRA_CFLAGS += -I$(src)/../unit
#~ EXTRA_CFLAGS += -I../include
#~ EXTRA_CFLAGS += -I../mod
#~ EXTRA_CFLAGS += -I../unit

MOD_DIR = ../mod
UNIT_DIR = ../unit

obj-m += TESTfiltering.o
TESTfiltering-objs += nf_nat64_filtering_and_updating_test.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_ipv4_pool.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_ipv6_hdr_iterator.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_pool6.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_config.o
TESTfiltering-objs += $(MOD_DIR)/xt_nat64_config_proto.o
TESTfiltering-objs += $(MOD_DIR)/xt_nat64_module_conf_validation.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_session.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_types.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_bib.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_rfc6052.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_send_packet.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_translate_packet.o
TESTfiltering-objs += $(MOD_DIR)/nf_nat64_static_routes.o
TESTfiltering-objs += $(UNIT_DIR)/unit_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
