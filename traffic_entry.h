#ifndef TRAFFIC_ENTRY_H
#define TRAFFIC_ENTRY_H

typedef struct _traffic_entry {
	struct _traffic_entry *pre, *next;
	unsigned int saddr;
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
	long int load;
}traffic_entry_t;

/* TODO: should implement a hash list incress search speed */

/* alloc meme */
int traffic_entry_init();
traffic_entry_t *traffic_entry_new(unsigned int saddr, unsigned int daddr, 
		unsigned short sport, unsigned short dport);
traffic_entry_t *traffic_entry_search_saddr(unsigned int saddr);
traffic_entry_t *traffic_entry_search_daddr(unsigned int daddr);
int traffic_entry_destory();

#endif
