#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x53eda548, "module_layout" },
	{ 0x4c8f63bd, "xt_unregister_target" },
	{ 0xba66affe, "kmalloc_caches" },
	{ 0x20eadeb6, "ip_compute_csum" },
	{ 0x78f9b710, "nf_ct_l3proto_try_module_get" },
	{ 0x6d40a921, "need_ipv4_conntrack" },
	{ 0xe1d81fc4, "__pskb_pull_tail" },
	{ 0x27e1a049, "printk" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xd82cd585, "xt_register_target" },
	{ 0x888e6174, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x6e224a7a, "need_conntrack" },
	{ 0xaccabc6a, "in4_pton" },
	{ 0x33e4cbc6, "kmem_cache_alloc_trace" },
	{ 0x236c8c64, "memcpy" },
	{ 0x75f9f5e8, "nf_ct_l3proto_find_get" },
	{ 0x40c68edd, "nf_ct_get_tuple" },
	{ 0x38d21d9, "skb_put" },
	{ 0xdb0e08a2, "nf_ct_l3proto_put" },
	{ 0x3dcfaf41, "__nf_ct_l4proto_find" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=x_tables,nf_conntrack,nf_conntrack_ipv4";


MODULE_INFO(srcversion, "5D457C1035F6A700697323A");
