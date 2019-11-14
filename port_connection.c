/*
   build it as kernel module, and use it to find which process is
   visting destination port

   Copyright @ zhenwei pi

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/sysctl.h>
#include <linux/version.h>

static unsigned int min_port = 0;
static unsigned int max_port = 65535;
static unsigned int sysctl_udp_port_connection = 0;
static unsigned int sysctl_tcp_port_connection = 0;
static struct ctl_table_header *ctl_header = NULL;

static struct ctl_table port_conn_table[] = {
	{
		.procname	= "udp_port_connection",
		.data		= &sysctl_udp_port_connection,
		.maxlen		= sizeof(sysctl_udp_port_connection),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_port,
		.extra2		= &max_port,
	},
	{
		.procname	= "tcp_port_connection",
		.data		= &sysctl_tcp_port_connection,
		.maxlen		= sizeof(sysctl_tcp_port_connection),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_port,
		.extra2		= &max_port,
	},
	{
	}
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
unsigned int __port_connection_hookfn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#else
unsigned int __port_connection_hookfn(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#endif
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);

	/*
	printk(KERN_INFO"%d, protocol = %d,  src IP %pI4\n",
		__LINE__, iph->protocol, &iph->saddr);
	*/
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (udph->dest == ntohs(sysctl_udp_port_connection)) {
			printk(KERN_INFO"UDP : pid = %d, comm = %s\n",
				current->pid, current->comm);
		}
	} else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (tcph->dest == ntohs(sysctl_tcp_port_connection)) {
			printk(KERN_INFO"TCP : pid = %d, comm = %s\n",
				current->pid, current->comm);
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops port_conn_hook = {
	.hook = __port_connection_hookfn,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
	//.owner = THIS_MODULE,
};

static int __init nf_init(void)
{
	int err = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	err = nf_register_net_hook(&init_net, &port_conn_hook);
#else
	err = nf_register_hook(&port_conn_hook);
#endif
	if (err) {
		printk(KERN_ERR"nf_register_hook() failed\n");
		goto out;
	}

	ctl_header = register_net_sysctl(&init_net, "net/ipv4",
			port_conn_table);
	if (ctl_header == NULL) {
		err = -ENOMEM;
		goto unregister_hook;
	}

	goto out;

unregister_hook :
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_unregister_net_hook(&init_net, &port_conn_hook);
#else
	nf_unregister_hook(&port_conn_hook);
#endif

out :
	return err;
}

static void __exit nf_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_unregister_net_hook(&init_net, &port_conn_hook);
#else
	nf_unregister_hook(&port_conn_hook);
#endif
	unregister_net_sysctl_table(ctl_header);
	ctl_header = NULL;
}

module_init(nf_init);
module_exit(nf_exit);
MODULE_AUTHOR("zhenwei pi p_ace@126.com");
MODULE_LICENSE("GPL");
