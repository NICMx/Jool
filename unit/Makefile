MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING

ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


ITERATOR = iterator
HASHTABLE = hashtable
RFC6052 = rfc6052
PKT = pkt
FRAGDB = fragdb
POOLNUM = poolnum
POOL4 = pool4
BIB_SESSION = bib_session
INCOMING = incoming
FILTERING = filtering
OUTGOING = outgoing
TRANSLATE = translate
HAIRPINNING = hairpinning
SEND = send


obj-m += $(ITERATOR).o
obj-m += $(HASHTABLE).o
obj-m += $(RFC6052).o
obj-m += $(PKT).o
obj-m += $(FRAGDB).o
obj-m += $(POOLNUM).o
obj-m += $(POOL4).o
obj-m += $(BIB_SESSION).o
obj-m += $(INCOMING).o
obj-m += $(FILTERING).o
obj-m += $(OUTGOING).o
obj-m += $(TRANSLATE).o
obj-m += $(HAIRPINNING).o
obj-m += $(SEND).o

$(ITERATOR)-objs += ../mod/types.o
$(ITERATOR)-objs += ../mod/str_utils.o
$(ITERATOR)-objs += framework/unit_test.o
$(ITERATOR)-objs += ipv6_hdr_iterator_test.o

$(HASHTABLE)-objs += ../mod/types.o
$(HASHTABLE)-objs += ../mod/str_utils.o
$(HASHTABLE)-objs += framework/unit_test.o
$(HASHTABLE)-objs += hash_table_test.o

$(RFC6052)-objs += ../mod/types.o
$(RFC6052)-objs += ../mod/str_utils.o
$(RFC6052)-objs += framework/unit_test.o
$(RFC6052)-objs += rfc6052_test.o

$(PKT)-objs += ../mod/types.o
$(PKT)-objs += ../mod/str_utils.o
$(PKT)-objs += framework/unit_test.o
$(PKT)-objs += packet_test.o

$(FRAGDB)-objs += ../mod/types.o
$(FRAGDB)-objs += ../mod/str_utils.o
$(FRAGDB)-objs += ../mod/random.o
$(FRAGDB)-objs += ../mod/ipv6_hdr_iterator.o
$(FRAGDB)-objs += ../mod/packet.o
$(FRAGDB)-objs += ../mod/icmp_wrapper.o
$(FRAGDB)-objs += framework/unit_test.o
$(FRAGDB)-objs += framework/skb_generator.o
$(FRAGDB)-objs += framework/types.o
$(FRAGDB)-objs += fragment_db_test.o

$(POOLNUM)-objs += ../mod/types.o
$(POOLNUM)-objs += ../mod/str_utils.o
$(POOLNUM)-objs += ../mod/random.o
$(POOLNUM)-objs += framework/unit_test.o
$(POOLNUM)-objs += pool_num_test.o

$(POOL4)-objs += ../mod/types.o
$(POOL4)-objs += ../mod/str_utils.o
$(POOL4)-objs += ../mod/random.o
$(POOL4)-objs += ../mod/poolnum.o
$(POOL4)-objs += framework/unit_test.o
$(POOL4)-objs += pool4_test.o

$(BIB_SESSION)-objs += ../mod/types.o
$(BIB_SESSION)-objs += ../mod/str_utils.o
$(BIB_SESSION)-objs += ../mod/icmp_wrapper.o
$(BIB_SESSION)-objs += ../mod/rfc6052.o
$(BIB_SESSION)-objs += ../mod/pool6.o
$(BIB_SESSION)-objs += framework/impersonator_pool4.o
$(BIB_SESSION)-objs += ../mod/bib_db.o
$(BIB_SESSION)-objs += ../mod/filtering_and_updating.o
$(BIB_SESSION)-objs += framework/unit_test.o
$(BIB_SESSION)-objs += framework/impersonator_send_packet.o
$(BIB_SESSION)-objs += bib_session_test.o

$(INCOMING)-objs += ../mod/types.o
$(INCOMING)-objs += ../mod/str_utils.o
$(INCOMING)-objs += ../mod/ipv6_hdr_iterator.o
$(INCOMING)-objs += ../mod/packet.o
$(INCOMING)-objs += ../mod/icmp_wrapper.o
$(INCOMING)-objs += framework/unit_test.o
$(INCOMING)-objs += framework/skb_generator.o
$(INCOMING)-objs += framework/types.o
$(INCOMING)-objs += determine_incoming_tuple_test.o

$(FILTERING)-objs += ../mod/types.o
$(FILTERING)-objs += ../mod/str_utils.o
$(FILTERING)-objs += ../mod/packet.o
$(FILTERING)-objs += ../mod/icmp_wrapper.o
$(FILTERING)-objs += ../mod/ipv6_hdr_iterator.o
$(FILTERING)-objs += ../mod/rfc6052.o
$(FILTERING)-objs += ../mod/pool6.o
$(FILTERING)-objs += ../mod/bib_db.o
$(FILTERING)-objs += ../mod/session_db.o
$(FILTERING)-objs += ../mod/send_packet.o
$(FILTERING)-objs += framework/impersonator_pool4.o
$(FILTERING)-objs += framework/skb_generator.o
$(FILTERING)-objs += framework/unit_test.o
$(FILTERING)-objs += framework/types.o
$(FILTERING)-objs += filtering_and_updating_test.o

$(OUTGOING)-objs += ../mod/types.o
$(OUTGOING)-objs += ../mod/str_utils.o
$(OUTGOING)-objs += ../mod/icmp_wrapper.o
$(OUTGOING)-objs += ../mod/rfc6052.o
$(OUTGOING)-objs += ../mod/pool6.o
$(OUTGOING)-objs += ../mod/bib_db.o
$(OUTGOING)-objs += framework/impersonator_pool4.o
$(OUTGOING)-objs += framework/unit_test.o
$(OUTGOING)-objs += compute_outgoing_tuple_test.o

$(TRANSLATE)-objs += ../mod/types.o
$(TRANSLATE)-objs += ../mod/str_utils.o
$(TRANSLATE)-objs += ../mod/packet.o
$(TRANSLATE)-objs += ../mod/ipv6_hdr_iterator.o
$(TRANSLATE)-objs += ../mod/icmp_wrapper.o
$(TRANSLATE)-objs += framework/unit_test.o
$(TRANSLATE)-objs += framework/skb_generator.o
$(TRANSLATE)-objs += framework/validator.o
$(TRANSLATE)-objs += framework/types.o
$(TRANSLATE)-objs += translate_packet_test.o

$(HAIRPINNING)-objs += ../mod/types.o
$(HAIRPINNING)-objs += ../mod/str_utils.o
$(HAIRPINNING)-objs += ../mod/random.o
$(HAIRPINNING)-objs += ../mod/ipv6_hdr_iterator.o
$(HAIRPINNING)-objs += ../mod/rfc6052.o
$(HAIRPINNING)-objs += ../mod/packet.o
$(HAIRPINNING)-objs += ../mod/fragment_db.o
$(HAIRPINNING)-objs += ../mod/pool6.o
$(HAIRPINNING)-objs += ../mod/bib_db.o
$(HAIRPINNING)-objs += ../mod/session_db.o
$(HAIRPINNING)-objs += ../mod/determine_incoming_tuple.o
$(HAIRPINNING)-objs += ../mod/filtering_and_updating.o
$(HAIRPINNING)-objs += ../mod/compute_outgoing_tuple.o
$(HAIRPINNING)-objs += ../mod/translate_packet.o
$(HAIRPINNING)-objs += ../mod/handling_hairpinning.o
$(HAIRPINNING)-objs += ../mod/core.o
$(HAIRPINNING)-objs += ../mod/icmp_wrapper.o
$(HAIRPINNING)-objs += framework/unit_test.o
$(HAIRPINNING)-objs += framework/skb_generator.o
$(HAIRPINNING)-objs += framework/types.o
$(HAIRPINNING)-objs += framework/bib_session_helper.o
$(HAIRPINNING)-objs += framework/impersonator_pool4.o
$(HAIRPINNING)-objs += framework/impersonator_send_packet.o
$(HAIRPINNING)-objs += handling_hairpinning_test.o

# Send packet (does not have a unit test, so just make sure it compiles.)
$(SEND)-objs += ../mod/ipv6_hdr_iterator.o
$(SEND)-objs += ../mod/send_packet.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod $(ITERATOR).ko && sudo rmmod $(ITERATOR)
	-sudo insmod $(HASHTABLE).ko && sudo rmmod $(HASHTABLE)
	-sudo insmod $(RFC6052).ko && sudo rmmod $(RFC6052)
	-sudo insmod $(PKT).ko && sudo rmmod $(PKT)
	-sudo insmod $(FRAGDB).ko && sudo rmmod $(FRAGDB)
	-sudo insmod $(POOLNUM).ko && sudo rmmod $(POOLNUM)
	-sudo insmod $(POOL4).ko && sudo rmmod $(POOL4)
	-sudo insmod $(BIB_SESSION).ko && sudo rmmod $(BIB_SESSION)
	-sudo insmod $(INCOMING).ko && sudo rmmod $(INCOMING)
	-sudo insmod $(FILTERING).ko && sudo rmmod $(FILTERING)
	-sudo insmod $(OUTGOING).ko && sudo rmmod $(OUTGOING)
	-sudo insmod $(TRANSLATE).ko && sudo rmmod $(TRANSLATE)
	-sudo insmod $(HAIRPINNING).ko && sudo rmmod $(HAIRPINNING)
	dmesg | grep 'Finished.'
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f  ../mod/*.o  *.ko  *.o
