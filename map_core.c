#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/socket.h>/*PF_INET*/
#include <linux/netfilter_ipv4.h>/*NF_IP_PRE_FIRST*/
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h> /*in_aton()*/
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/timer.h>
#include "traffic_entry.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("brytonlee01@gmail.com");

#ifndef NIPQUAD
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#define TCPHDR(skb) ((char*)(skb)->data+iph->ihl*4)

struct nf_hook_ops nf_pre_route; 
struct nf_hook_ops nf_out;

#define PORTS_MAX 20
static unsigned short ports_array[PORTS_MAX];
int narr;

static struct timer_list traffic_timer;

module_param_array(ports_array, ushort, &narr, 0644);
MODULE_PARM_DESC(ports_array, "ports_array: pass a port array to traffic_map module.");

void entry_dump(unsigned long data)
{
	int ret = 0;

	traffic_entry_dump();

	ret = mod_timer(&traffic_timer, jiffies + msecs_to_jiffies(30 * 1000) );
	if (ret) printk("Error in mod_timer\n");
}

static void tcp_record(const struct sk_buff *skb, const struct iphdr *iph, 
	const struct tcphdr *tcph)
{
//	unsigned int daddr;
//	unsigned int saddr;
//	unsigned short sport;
//	unsigned short dport;
	traffic_entry_t *entry = NULL;

	int tot_len; /* packet data totoal length */
	int iph_len;
	int tcph_len;
	int tcp_load;

	tot_len = ntohs(iph->tot_len);
	iph_len = ip_hdrlen(skb);
	tcph_len = tcph->doff * 4;
	tcp_load = tot_len - ( iph_len + tcph_len );

	//saddr = ntohl(iph->saddr);
	//daddr = ntohl(iph->daddr);
	//sport = ntohs(tcph->source);
	//dport = ntohs(tcph->dest);

	entry = traffic_entry_search(iph->saddr, iph->daddr);	
	if ( entry ) {
		entry->load += tcp_load;
	} else {
		entry = traffic_entry_new(iph->saddr, iph->daddr, tcph->source, tcph->dest);
		if ( !entry ) {
			//printk("alloc memory failed!\n");
			return;
		}	
		entry->load = tcp_load;
	}

}

static void tcp_info(const struct sk_buff *skb, const struct iphdr *iph,
	const struct tcphdr *tcph)
{
	int tot_len; /* packet data totoal length */
	int iph_len;
	int tcph_len;
	int tcp_load;

	tot_len = ntohs(iph->tot_len);
	iph_len = ip_hdrlen(skb);
	tcph_len = tcph->doff * 4;
	tcp_load = tot_len - ( iph_len + tcph_len );

	/* debug */
//	printk("total_len: %d, iph_len: %d, tcph_len: %d\n",
//		tot_len, iph_len, tcph_len);

	printk("tcp connection and src: "NIPQUAD_FMT":%d, dest: "NIPQUAD_FMT
			":%d, load_length: %d\n",
		NIPQUAD(iph->saddr), ntohs(tcph->source),
		NIPQUAD(iph->daddr), ntohs(tcph->dest), tcp_load);
}

/* output */
#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
unsigned int filter_out(unsigned int hooknum,
                        struct sk_buff *__skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
#else
unsigned int filter_out(unsigned int hooknum,
                        struct sk_buff **__skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
#endif
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned short port;
	int i;

#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	skb = __skb;
#else 
	skb = *__skb;
#endif

	if(skb == NULL)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if(iph == NULL)
		return NF_ACCEPT;

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph=(struct tcphdr*)TCPHDR(skb);

		for ( i = 0; i < narr; i++ ) {
			port = ports_array[i];
			if ( tcph->source == htons(port) )
				//tcp_info(skb, iph, tcph);
				tcp_record(skb, iph, tcph);
		}
	}
	
	return NF_ACCEPT;
}

/* input */
#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
unsigned int filter_pre_route(unsigned int hooknum,
                        struct sk_buff *__skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
#else
unsigned int filter_pre_route(unsigned int hooknum,
                        struct sk_buff **__skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
#endif
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned short port;
	int i;

#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	skb = __skb;
#else 
	skb = *__skb;
#endif

	if(skb == NULL)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if(iph == NULL)
		return NF_ACCEPT;

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph=(struct tcphdr*)TCPHDR(skb);

		for ( i = 0; i < narr; i++ ) {
			port = ports_array[i];
			if ( tcph->dest == htons(port) )
				//tcp_info(skb, iph, tcph);
				tcp_record(skb, iph, tcph);
		}

	}
	return NF_ACCEPT;
}

static int __init filter_init(void)
{
	int i;
	int ret;

	printk("traffic_map used to monitor tcp connections traffic\n"
		"Author: brytonlee01@gmail.com\n");

	/* init listen port */
	if ( narr > PORTS_MAX ) {
		printk("too many ports\n");
		return -1;
	}
	
	for ( i = 0; i < narr; i++ ) {
		/* TODO check port valid ,sort ,uniq*/
		printk("ports_array[%d] = %u\n", i, ports_array[i]);
	}	

	/* init struct caceh */
	traffic_entry_init();

	/* input */
	nf_pre_route.hook = filter_pre_route;
	nf_pre_route.pf = AF_INET;
#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	nf_pre_route.hooknum = NF_INET_PRE_ROUTING;
#else
	nf_pre_route.hooknum = NF_IP_PRE_ROUTING;
#endif
	nf_pre_route.priority = NF_IP_PRI_FIRST;

	ret = nf_register_hook(&nf_pre_route);
	if(ret < 0)
	{
		printk("%s\n", "can't modify skb hook!");
		return ret;
	}

	/* output */
	nf_out.hook = filter_out;
	nf_out.pf = AF_INET;
#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	nf_out.hooknum = NF_INET_LOCAL_OUT;
#else
	nf_out.hooknum = NF_IP_LOCAL_OUT;
#endif 
	
	ret = nf_register_hook(&nf_out);
	if ( ret < 0 ) {
		printk("%s\n", "can't modify skb hook!");
		return ret;
	}
	
	/* install timer */
	setup_timer(&traffic_timer, entry_dump, 0);
	
	/* 30 seconds call timer function */
	ret = mod_timer(&traffic_timer, jiffies + msecs_to_jiffies(30 * 1000) );
	if (ret) printk("Error in mod_timer\n");

	return 0;
}

static void filter_fini(void)
{
	int ret = 0;

	ret = del_timer(&traffic_timer);
	if ( ret ) 
		printk("The traffic_timer is still in use...\n");

	traffic_entry_destory();
	nf_unregister_hook(&nf_pre_route);
	nf_unregister_hook(&nf_out);
	printk("[traffic_map]: bye...\n");
}
module_init(filter_init);
module_exit(filter_fini);
