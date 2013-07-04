#include "traffic_entry.h"
#include <linux/slab.h>

static kmem_cache_t *traffic_entry_cache=NULL;

int traffic_entry_init()
{
	int ret = -1;

	traffic_entry_cache = kmem_cache_create("traffic_entry_cache",
			sizeof(struct _traffic_entry), 0, NULL, NULL);
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
	
	return entry;
}

traffic_entry_t *traffic_entry_search_saddr(unsigned int saddr)
{
	traffic_entry_t *entry = NULL;
	
	return entry;
}

traffic_entry_t *traffic_entry_search_daddr(unsigned int daddr)
{
	traffic_entry_t *entry = NULL;
	
	return entry;
}

int traffic_entry_destory()
{
	int ret = -1;

	/* TODO: free cache list */

	if (traffic_entry_cache)
		kmem_cache_destory(traffic_entry_cache);
	
	ret = 0;
	return ret;
}
