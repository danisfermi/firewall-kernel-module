#include <linux/kernel.h> // For KERN_INFO
#include <linux/module.h> // For all Kernal Modules
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux Firewall Kernal Module");
MODULE_AUTHOR("Danis Fermi");

static struct nf_hook_ops nfhook;

// Firewall Rules
static unsigned char *ip_address = "\xC0\xA8\x00\x01"; // Network Byte Order 192.168.0.1
static char *interface = "lo"; //  Blocking Loopback Interface                     

struct sk_buff *sock_buff; // Pointer to socket kernel buffer                              
struct udphdr *udp_header; // Pointer to UDP header

// Function called by Hook
unsigned int hookfunc(unsigned int hooknum,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{
  // Filter Based on Interface. Block all packets to Loopback Interface
  if(strcmp(in->name, interface) == 0)
    return NF_DROP;

  // Filter Based on IP Packet
  if(!skb) // Not valid buffer
    return NF_ACCEPT;
  struct iphdr *ip_hdr = (struct iphdr *)skb_network_header(skb); // To get IP Protocol
  if(!ip_hdr)
    return NF_ACCEPT; // Not valid IP
  /*
    Drop if Source Address Matches 192.168.0.1 (use daddr for Destination Address)
  if(ip_hdr->saddr == *(unsigned int*)ip_address)
    return NF_DROP;
  */

  /* Filter for ICMP Packets
  ------------------------
  ICMP Types Dropped are (anything other than ICMP Echo Reply):-
  ------------------------
  ICMP_ECHO
  ICMP_ROUTERADVERT
  ICMP_ROUTERSOLICIT
  ICMP_TSTAMP
  ICMP_TSTAMPREPLY
  ICMP_IREQ
  ICMP_IREQREPLY
  ICMP_MASKREQ
  ICMP_MASKREPLY
  */
  if(ip_hdr->protocol == IPPROTO_ICMP)
      {
        struct icmphdr *icmph;
        icmph = icmp_hdr(skb);
        if(!icmph)
          return NF_ACCEPT;
        if(icmph->type != ICMP_ECHOREPLY)
          return NF_DROP;
      }

  // Filter for UDP Packets
  if(ip_hdr->protocol == IPPROTO_UDP)
      {
        struct udphdr *udph;
        udph = udp_hdr(skb);
        if(!udph)
          return NF_ACCEPT;
        unsigned int dst_port = (unsigned int)ntohs(udph->dest);
        if(dst_port == 135) // Block all UDP Traffic to Port 135(Windows RPC :P)
          return NF_DROP;
      }

  // Filter for TCP Packets
  if(ip_hdr->protocol == IPPROTO_TCP)
      {
        struct tcphdr *tcph;
        tcph = tcp_hdr(skb);
        if(!tcph) // Not valid TCP
          return NF_ACCEPT; 
        unsigned int dst_port = (unsigned int)ntohs(tcph->dest);
        if(dst_port == 22 && ip_hdr->saddr == *(unsigned int*)ip_address) // Block all SSH Traffic from 192.168.0.1
          return NF_DROP;
      }

    // No Match
    return NF_ACCEPT;
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