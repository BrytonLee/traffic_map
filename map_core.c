#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/socket.h>/*PF_INET*/
#include <linux/netfilter_ipv4.h>/*NF_IP_PRE_FIRST*/
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h> /*in_aton()*/
#include <net/ip.h>
#include <net/tcp.h>
#define ETHALEN 14
MODULE_LICENSE("GPL");
MODULE_AUTHOR("brytonlee01@gmail.com");
struct nf_hook_ops nfho; 

#ifndef NIPQUAD
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

#endif

#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
unsigned int checksum(unsigned int hooknum,
                        struct sk_buff *__skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
#else
unsigned int checksum(unsigned int hooknum,
                        struct sk_buff **__skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
#endif
    struct sk_buff *skb;
    //struct net_device *dev;
    struct iphdr *iph;
    struct tcphdr *tcph;
    //int tot_len;
    //int iph_len;
    //int tcph_len;
    int ret;
#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
    skb = __skb;
#else 
	skb = *__skb;
#endif

    if(skb == NULL)
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    if(iph == NULL)
        return NF_ACCEPT;

    //tot_len = ntohs(iph->tot_len);
	if(iph->protocol == IPPROTO_TCP)
	{
		//iph_len = ip_hdrlen(skb);
		//skb_pull(skb, iph_len);
		tcph = tcp_hdr(skb);

		//tcph_len = tcp_hdrlen(skb);
		if ( tcph->dest == htons(80) ) {
			printk("tcp connection and src: "NIPQUAD_FMT", dest: "NIPQUAD_FMT", port %d\n",
				NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), 80);
		} 

		//skb_push(skb, iph_len);
	}
	return NF_ACCEPT;
}
static int __init filter_init(void)
{
    int ret;
        nfho.hook = checksum;
        nfho.pf = AF_INET;
#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && \
	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
        nfho.hooknum = NF_INET_PRE_ROUTING;
#else
		nfho.hooknum = NF_IP_PRE_ROUTING;
#endif
        nfho.priority = NF_IP_PRI_FIRST;
    
        ret = nf_register_hook(&nfho);
        if(ret < 0)
        {
            printk("%s\n", "can't modify skb hook!");
            return ret;
        }
    return 0;
}
static void filter_fini(void)
{
    nf_unregister_hook(&nfho);
}
module_init(filter_init);
module_exit(filter_fini);
