MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -DDEBUG -DUNIT_TESTING

#CC=cgcc
ccflags-y := -I$(src)/../include
ccflags-y += -I$(src)/../mod


ITERATOR = iterator
HASHTABLE = hashtable
RFC6052 = rfc6052
PKT = pkt
RBTREE = rbtree
POOLNUM = poolnum
POOL4 = pool4
BIB = bib
SESSION = session
INCOMING = incoming
FILTERING = filtering
OUTGOING = outgoing
TRANSLATE = translate
HAIRPINNING = hairpinning


obj-m += $(ITERATOR).o
obj-m += $(HASHTABLE).o
obj-m += $(RFC6052).o
obj-m += $(PKT).o
obj-m += $(RBTREE).o
obj-m += $(POOLNUM).o
obj-m += $(POOL4).o
obj-m += $(BIB).o
obj-m += $(SESSION).o
obj-m += $(INCOMING).o
obj-m += $(FILTERING).o
obj-m += $(OUTGOING).o
obj-m += $(TRANSLATE).o
obj-m += $(HAIRPINNING).o


MIN_REQS = ../mod/types.o framework/str_utils.o framework/unit_test.o


$(ITERATOR)-objs += $(MIN_REQS)
$(ITERATOR)-objs += ipv6_hdr_iterator_test.o

$(HASHTABLE)-objs += $(MIN_REQS)
$(HASHTABLE)-objs += hash_table_test.o

$(RFC6052)-objs += $(MIN_REQS)
$(RFC6052)-objs += rfc6052_test.o

$(PKT)-objs += $(MIN_REQS)
$(PKT)-objs += ../mod/ipv6_hdr_iterator.o
$(PKT)-objs += ../mod/packet.o
$(PKT)-objs += framework/skb_generator.o
$(PKT)-objs += framework/types.o
$(PKT)-objs += impersonator/icmp_wrapper.o
$(PKT)-objs += packet_test.o

$(RBTREE)-objs += $(MIN_REQS)
$(RBTREE)-objs += rbtree_test.o

$(POOLNUM)-objs += $(MIN_REQS)
$(POOLNUM)-objs += ../mod/random.o
$(POOLNUM)-objs += pool_num_test.o

$(POOL4)-objs += $(MIN_REQS)
$(POOL4)-objs += ../mod/poolnum.o
$(POOL4)-objs += ../mod/random.o
$(POOL4)-objs += pool4_test.o

$(BIB)-objs += $(MIN_REQS)
# The BIB test cannot use the pool4 impersonator
# because it needs to test exhaustion.
$(BIB)-objs += ../mod/pool4.o
$(BIB)-objs += ../mod/poolnum.o
$(BIB)-objs += ../mod/random.o
$(BIB)-objs += framework/bib.o
$(BIB)-objs += framework/types.o
$(BIB)-objs += impersonator/icmp_wrapper.o
$(BIB)-objs += bib_test.o

$(SESSION)-objs += $(MIN_REQS)
$(SESSION)-objs += ../mod/bib_db.o
$(SESSION)-objs += ../mod/pool6.o
$(SESSION)-objs += ../mod/rfc6052.o
$(SESSION)-objs += ../mod/session_db.o
$(SESSION)-objs += impersonator/icmp_wrapper.o
$(SESSION)-objs += impersonator/pool4.o
$(SESSION)-objs += impersonator/send_packet.o
$(SESSION)-objs += session_test.o

$(INCOMING)-objs += $(MIN_REQS)
$(INCOMING)-objs += ../mod/ipv6_hdr_iterator.o
$(INCOMING)-objs += ../mod/packet.o
$(INCOMING)-objs += framework/skb_generator.o
$(INCOMING)-objs += framework/types.o
$(INCOMING)-objs += impersonator/icmp_wrapper.o
$(INCOMING)-objs += impersonator/stats.o
$(INCOMING)-objs += determine_incoming_tuple_test.o

$(FILTERING)-objs += $(MIN_REQS)
$(FILTERING)-objs += ../mod/bib_db.o
$(FILTERING)-objs += ../mod/ipv6_hdr_iterator.o
$(FILTERING)-objs += ../mod/packet.o
$(FILTERING)-objs += ../mod/pool6.o
$(FILTERING)-objs += ../mod/rfc6052.o
$(FILTERING)-objs += ../mod/session_db.o
$(FILTERING)-objs += framework/skb_generator.o
$(FILTERING)-objs += framework/types.o
$(FILTERING)-objs += impersonator/icmp_wrapper.o
$(FILTERING)-objs += impersonator/pool4.o
$(FILTERING)-objs += impersonator/send_packet.o
$(FILTERING)-objs += impersonator/stats.o
$(FILTERING)-objs += filtering_and_updating_test.o

$(OUTGOING)-objs += $(MIN_REQS)
$(OUTGOING)-objs += ../mod/bib_db.o
$(OUTGOING)-objs += ../mod/pool6.o
$(OUTGOING)-objs += ../mod/rfc6052.o
$(OUTGOING)-objs += impersonator/icmp_wrapper.o
$(OUTGOING)-objs += impersonator/pool4.o
$(OUTGOING)-objs += compute_outgoing_tuple_test.o

$(TRANSLATE)-objs += $(MIN_REQS)
$(TRANSLATE)-objs += ../mod/ipv6_hdr_iterator.o
$(TRANSLATE)-objs += ../mod/packet.o
$(TRANSLATE)-objs += framework/skb_generator.o
$(TRANSLATE)-objs += framework/types.o
$(TRANSLATE)-objs += framework/validator.o
$(TRANSLATE)-objs += impersonator/icmp_wrapper.o
$(TRANSLATE)-objs += impersonator/send_packet.o
$(TRANSLATE)-objs += impersonator/stats.o
$(TRANSLATE)-objs += translate_packet_test.o

$(HAIRPINNING)-objs += $(MIN_REQS)
$(HAIRPINNING)-objs += ../mod/bib_db.o
$(HAIRPINNING)-objs += ../mod/compute_outgoing_tuple.o
$(HAIRPINNING)-objs += ../mod/core.o
$(HAIRPINNING)-objs += ../mod/determine_incoming_tuple.o
$(HAIRPINNING)-objs += ../mod/filtering_and_updating.o
$(HAIRPINNING)-objs += ../mod/handling_hairpinning.o
$(HAIRPINNING)-objs += ../mod/ipv6_hdr_iterator.o
$(HAIRPINNING)-objs += ../mod/packet.o
$(HAIRPINNING)-objs += ../mod/pool6.o
$(HAIRPINNING)-objs += ../mod/random.o
$(HAIRPINNING)-objs += ../mod/rfc6052.o
$(HAIRPINNING)-objs += ../mod/session_db.o
$(HAIRPINNING)-objs += ../mod/translate_packet.o
$(HAIRPINNING)-objs += framework/bib.o
$(HAIRPINNING)-objs += framework/session.o
$(HAIRPINNING)-objs += framework/skb_generator.o
$(HAIRPINNING)-objs += framework/types.o
$(HAIRPINNING)-objs += impersonator/icmp_wrapper.o
$(HAIRPINNING)-objs += impersonator/pool4.o
$(HAIRPINNING)-objs += impersonator/send_packet.o
$(HAIRPINNING)-objs += impersonator/stats.o
$(HAIRPINNING)-objs += handling_hairpinning_test.o


all:
	make -C ${KERNEL_DIR} M=$$PWD;
test:
	-sudo insmod $(ITERATOR).ko && sudo rmmod $(ITERATOR)
	-sudo insmod $(HASHTABLE).ko && sudo rmmod $(HASHTABLE)
	-sudo insmod $(RFC6052).ko && sudo rmmod $(RFC6052)
	-sudo insmod $(PKT).ko && sudo rmmod $(PKT)
	-sudo insmod $(RBTREE).ko && sudo rmmod $(RBTREE)
	-sudo insmod $(POOLNUM).ko && sudo rmmod $(POOLNUM)
	# Warning: This test is lenghty! It might freeze your computer for a couple of seconds.
	-sudo insmod $(POOL4).ko && sudo rmmod $(POOL4)
	-sudo insmod $(BIB).ko && sudo rmmod $(BIB)
	-sudo insmod $(SESSION).ko && sudo rmmod $(SESSION)
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
