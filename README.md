# Linux Firewall using Kernel Module

## Building & Cleaning Module

To build this module, type:
`make`
To clean up the module, type:
`make clean`

## Loading & Unloading Module

To install the module, type
`sudo insmod simple_firewall.ko`
To remove the module, type:
`sudo rmmod simple_firewall`
To verify the module is actually loaded or unloaded, type:
`dmesg | tail`

## Module Information

1. Module to Drop All packets
2. Module to Drop Based on Different Filters
3. Module to Get Rules from User

## Theory

Netfilter is a packet filtering subsystem in the Linux kernel stack and has been there since kernel 2.4.x. Netfilter's core consists of five hook functions declared in linux/netfilter_ipv4.h. Although these functions are for IPv4, they aren't much different from those used in the IPv6 counterpart. The hooks are used to analyze packets in various locations on the network stack. This situation is depicted below:
```
  [INPUT]--->[1]--->[ROUTE]--->[3]--->[4]--->[OUTPUT]
                       |            ^
                       |            |
                       |         [ROUTE]
                       v            |
                      [2]          [5]
                       |            ^
                       |            |
                       v            |
                    [INPUT*]    [OUTPUT*]
                    
[1]  NF_IP_PRE_ROUTING (Right after the packets have been received. )
[2]  NF_IP_LOCAL_IN (Packets addressed to the network stack. )
[3]  NF_IP_FORWARD (Packets that should be forwarded. )
[4]  NF_IP_POST_ROUTING (Packets that have been routed and are ready to leave)
[5]  NF_IP_LOCAL_OUT (Packets from our own network stack)
[*]  Network Stack
```

Our hook function will return one of the following codes:-
1. NF_ACCEPT: accept the packet (continue network stack trip)
2. NF_DROP: drop the packet (don't continue trip)
3. NF_REPEAT: repeat the hook function
4. NF_STOLEN: hook steals the packet (don't continue trip)
5. NF_QUEUE: queue the packet to userspace

After we write our hook function, we have to register its options with the nf_hook_ops struct located in linux/netfilter.h.
```
struct nf_hook_ops
{
        struct list_head list;
        nf_hookfn *hook;
        int pf;
        int hooknum;
        int priority;
};

[1] list_head struct is used to keep a linked list of hooks
[2] nf_hookfn* struct member is the name of the hook function that we define
[3] pf integer member is used to identify the protocol family; it's PF_INET for IPv4
[4] hooknum (int) is for the hook we want to use
[5] priority (int) specifies in linux/netfilter_ipv4.h, but for our situation we want NF_IP_PRI_FIRST
```

The rest of the code is pretty self explanatory. In-line comments are provided for assistance.

## To Do

Minifirewall, using the proc file system to accept firewall rules from the user space.
