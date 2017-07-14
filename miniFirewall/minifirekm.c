#include <linux/kernel.h> // For KERN_INFO
#include <linux/module.h> // For all Kernal Modules
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux Firewall Kernal Module");
MODULE_AUTHOR("Danis Fermi");

static struct nf_hook_ops nfhook;

// Function called by Hook
unsigned int hookfunc(unsigned int hooknum,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{
    return NF_DROP; // Drop all packets
}

// Called when module is loaded using 'insmod'
int init_module()
{
    nfhook.hook = hookfunc; // Call hookfunc if match condition
    nfhook.hooknum = NF_INET_PRE_ROUTING; // After sanity checks, before routing decisions
    nfhook.pf = PF_INET; // Protocol Family IPv4
    nfhook.priority = NF_IP_PRI_FIRST; // Placement of hook function in the order of execution
    nf_register_hook(&nfhook);
    printk(KERN_INFO "Loaded Firewall to Kernal Module\n");
    return 0;
} 

// Called when module is Unloaded using 'rmmod'
void cleanup_module()
{
    printk(KERN_INFO "Unloading Firewall to Kernal Module\n");
    nf_unregister_hook(&nfhook);
}