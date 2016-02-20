#include "device_name.h"

#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#include "types.h"

struct device_name {
	char *name;
	struct list_head list;
};

static struct list_head device_list;
static DEFINE_SPINLOCK(dev_lock);

int dev_init(void) {
	INIT_LIST_HEAD(&device_list);
	return 0;
}

static void kfree_device_name(struct device_name *dev) {
	kfree(dev->name);
	kfree(dev);
	return;
}

static void flush(struct list_head *root, bool sync)
{
	struct device_name *dev;

	if (sync)
		spin_lock_bh(&dev_lock);

	while (!list_empty(root)) {
		dev = list_first_entry(root, struct device_name, list);
		if (!dev)
			continue;
		list_del(&dev->list);
		kfree_device_name(dev);
	}

	if (sync)
		spin_unlock_bh(&dev_lock);
}

void dev_destroy(void) {
	flush(&device_list, false);
}

int dev_flush(void) {
	flush(&device_list, true);
	return 0;
}

int dev_add(char *dev_name, __u32 str_len)
{
	struct device_name *entry;
	int gap;

	if (!dev_name) {
		log_err("dev_name can't be null.");
		return -EINVAL;
	}

	spin_lock_bh(&dev_lock);

	list_for_each_entry(entry, &device_list, list) {
		gap = strcmp(entry->name, dev_name);
		if (!gap) {
			spin_unlock_bh(&dev_lock);
			log_err("%s exists, try another device name.", dev_name);
			return -EINVAL;
		}
	}
	spin_unlock_bh(&dev_lock);

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		log_err("failed to allocate memory.");
		return -ENOMEM;
	}

	entry->name = kmalloc(str_len, GFP_KERNEL);
	if (!entry->name) {
		kfree(entry);
		log_err("failed to allocate memory.");
		return -ENOMEM;
	}
	memcpy(entry->name, dev_name, str_len);

	spin_lock_bh(&dev_lock);
	list_add_tail(&entry->list, &device_list);
	spin_unlock_bh(&dev_lock);

	log_debug("%s inserted.", dev_name);
	return 0;

}

int dev_remove(char *dev_name)
{
	struct device_name *entry, *tmp;
	int gap;

	if (!dev_name) {
		log_err("dev_name can't be null.");
		return -EINVAL;
	}

	spin_lock_bh(&dev_lock);
	if (list_empty(&device_list)) {
		spin_unlock_bh(&dev_lock);
		log_info("List is empty.");
		return 0;
	}

	list_for_each_entry_safe(entry, tmp, &device_list, list) {
		gap = strcmp(dev_name, entry->name);
		if (!gap) {
			list_del(&entry->list);
			spin_unlock_bh(&dev_lock);
			kfree_device_name(entry);
			return 0;
		}
	}

	spin_unlock_bh(&dev_lock);

	log_err("%s not found.", dev_name);
	return -ESRCH;
}

int dev_display(void)
{
	struct device_name *entry;
	int i = 0;

	spin_lock_bh(&dev_lock);
	list_for_each_entry(entry, &device_list, list) {
		i++;
		log_info(" %d - %s", i, entry->name);
	}
	spin_unlock_bh(&dev_lock);

	return 0;
}

int dev_name_filter(char *skb_dev_name)
{
	struct device_name *entry;
	int gap;

	if (!skb_dev_name) {
		log_err("skb_dev_name can't be null.");
		return -EINVAL;
	}

	spin_lock_bh(&dev_lock);
	if (list_empty(&device_list)) {
		spin_unlock_bh(&dev_lock);
		return 0; /* nothing to be filter. */
	}

	list_for_each_entry(entry, &device_list, list) {
		gap = strcmp(skb_dev_name, entry->name);
		if (!gap) {
			spin_unlock_bh(&dev_lock);
			return 0;
		}
	}

	spin_unlock_bh(&dev_lock);
	return -ESRCH;
}
