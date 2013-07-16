#include "traffic_entry.h"
#include <linux/version.h>
#include <linux/slab.h>

#ifndef NIPQUAD
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

static struct kmem_cache *traffic_entry_cache=NULL;
static LIST_HEAD(traffic_entry_head);

int traffic_entry_init()
{
	int ret = -1;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
/*----------------------------------------------------------------------------
 * In 2.6.23, the last argument was dropped from kmem_cache_create. */
	traffic_entry_cache = kmem_cache_create("traffic_entry_cache",
			sizeof(struct _traffic_entry), 0, 0, NULL, NULL);
#else
	traffic_entry_cache = kmem_cache_create("traffic_entry_cache",
			sizeof(struct _traffic_entry), 0, 0, NULL);
#endif
	if ( !traffic_entry_cache ) {
		printk("kmem_cache_create error\n");
		return ret;
	}

	return ret;
}

traffic_entry_t *traffic_entry_new(unsigned int saddr, unsigned int daddr, 
		unsigned short sport, unsigned short dport)
{
	traffic_entry_t *entry = NULL;
	
	if ( !traffic_entry_cache ) {
		return NULL;
	}
	entry = (traffic_entry_t *) kmem_cache_alloc(traffic_entry_cache, GFP_KERNEL);
	if ( !entry )  {
		printk("[traffic_map]: traffic_entry_new alloc memory failed!\n");
		return entry;
	}
	
	entry->saddr = saddr;
	entry->daddr = daddr;
	entry->sport = sport;
	entry->dport = dport;
	entry->load = 0;
	
	INIT_LIST_HEAD(&entry->list);
	list_add(&entry->list, &traffic_entry_head);
	
	return entry;
}

traffic_entry_t *traffic_entry_search(const unsigned int saddr,
	const unsigned int daddr)
{
	traffic_entry_t *entry = NULL;

	if ( !traffic_entry_cache ) {
		return NULL;
	}
	
	list_for_each_entry(entry, &traffic_entry_head, list) {
		if ( entry->saddr == saddr && entry->daddr == daddr )
			return entry;
	}
	
	return NULL;
}

traffic_entry_t *traffic_entry_search_saddr(unsigned int saddr)
{
	traffic_entry_t *entry = NULL;

	if ( !traffic_entry_cache ) {
		return NULL;
	}
	
	list_for_each_entry(entry, &traffic_entry_head, list) {
		if ( entry->saddr == saddr )
			return entry;
	}
	
	return NULL;
}

traffic_entry_t *traffic_entry_search_daddr(unsigned int daddr)
{
	traffic_entry_t *entry = NULL;
	
	if ( !traffic_entry_cache ) {
		return NULL;
	}
	
	list_for_each_entry(entry, &traffic_entry_head, list) {
		if ( entry->daddr == daddr )
			return entry;
	}
	return NULL;
}

void traffic_entry_dump(void)
{
	traffic_entry_t *entry = NULL;

	/* print banner */
	printk("saddr:\t\tdaddr:\t\tsport:\t\tdport:\t\tload\n");
	printk("=================================================================\n");
	if ( !list_empty(&traffic_entry_head) ) {
		list_for_each_entry(entry, &traffic_entry_head, list) {
			printk(NIPQUAD_FMT"\t"NIPQUAD_FMT"\t%d\t\t%d\t\t%ld\n",
				NIPQUAD(entry->saddr), NIPQUAD(entry->daddr),
				ntohs(entry->sport), ntohs(entry->dport),
				entry->load);
		}
	}
		
}

int traffic_entry_destory()
{
	traffic_entry_t *entry = NULL;
	traffic_entry_t *entry2 = NULL;
	int ret = -1;

	list_for_each_entry_safe(entry, entry2, &traffic_entry_head, list) {
		list_del(&entry->list);
		kmem_cache_free(traffic_entry_cache, entry);
	}

	if (traffic_entry_cache)
		kmem_cache_destroy(traffic_entry_cache);
	
	ret = 0;
	return ret;
}
