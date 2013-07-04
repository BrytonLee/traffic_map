#include "traffic_entry.h"
#include <linux/version.h>
#include <linux/slab.h>

static struct kmem_cache *traffic_entry_cache=NULL;

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
		kmem_cache_destroy(traffic_entry_cache);
	
	ret = 0;
	return ret;
}
