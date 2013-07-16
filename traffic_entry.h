#ifndef _TRAFFIC_ENTRY_H
#define _TRAFFIC_ENTRY_H
#include <linux/list.h>

typedef struct _traffic_entry {
	struct list_head list;
	unsigned int saddr;
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
	long int load;
}traffic_entry_t;

/* alloc memory */
extern int traffic_entry_init(void);
extern traffic_entry_t *traffic_entry_new(unsigned int saddr, unsigned int daddr, 
		unsigned short sport, unsigned short dport);
extern traffic_entry_t *traffic_entry_search_saddr(unsigned int saddr);
extern traffic_entry_t *traffic_entry_search_daddr(unsigned int daddr);
extern int traffic_entry_destory(void);
extern traffic_entry_t *traffic_entry_search(const unsigned int saddr,
	const unsigned int daddr);

extern void traffic_entry_dump(void);

#endif
