// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Pseudo-driver for the loopback interface.
 *
 * Version:	@(#)loopback.c	1.0.4b	08/16/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@scyld.com>
 *
 *		Alan Cox	:	Fixed oddments for NET3.014
 *		Alan Cox	:	Rejig for NET3.029 snap #3
 *		Alan Cox	:	Fixed NET3.029 bugs and sped up
 *		Larry McVoy	:	Tiny tweak to double performance
 *		Alan Cox	:	Backed out LMV's tweak - the linux mm
 *					can't take it...
 *              Michael Griffith:       Don't bother computing the checksums
 *                                      on packets received on the loopback
 *                                      interface.
 *		Alexey Kuznetsov:	Potential hang under some extreme
 *					cases removed.
 */
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>

#include <linux/uaccess.h>
#include <linux/io.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <linux/if_ether.h>	/* For the statistics structure. */
#include <linux/if_arp.h>	/* For ARPHRD_ETHER */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/percpu.h>
#include <linux/net_tstamp.h>
#include <net/net_namespace.h>
#include <linux/u64_stats_sync.h>

#define Device_Name "cas_vnet"

static struct net_device *vnet_dev;

/* The higher levels take care of making this non-reentrant (it's
 * called with bh's disabled).
 */
static netdev_tx_t cas_vnet_xmit(struct sk_buff *skb,
				 struct net_device *dev)
{
	struct pcpu_lstats *lb_stats;
	int len;
	printk("here we are!\n\n");
	skb_tx_timestamp(skb);

	/* do not fool net_timestamp_check() with various clock bases */
	skb->tstamp = 0;

	skb_orphan(skb);

	/* Before queueing this packet to netif_rx(),
	 * make sure dst is refcounted.
	 */
	skb_dst_force(skb);

	skb->protocol = eth_type_trans(skb, dev);

	/* it's OK to use per_cpu_ptr() because BHs are off */
	lb_stats = this_cpu_ptr(dev->lstats);

	len = skb->len;
	if (likely(netif_rx(skb) == NET_RX_SUCCESS)) {
		u64_stats_update_begin(&lb_stats->syncp);
		lb_stats->bytes += len;
		lb_stats->packets++;
		u64_stats_update_end(&lb_stats->syncp);
	}

	return NETDEV_TX_OK;
}

static void cas_vnet_get_stats64(struct net_device *dev,
				 struct rtnl_link_stats64 *stats)
{
	u64 bytes = 0;
	u64 packets = 0;
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_lstats *lb_stats;
		u64 tbytes, tpackets;
		unsigned int start;

		lb_stats = per_cpu_ptr(dev->lstats, i);
		do {
			start = u64_stats_fetch_begin_irq(&lb_stats->syncp);
			tbytes = lb_stats->bytes;
			tpackets = lb_stats->packets;
		} while (u64_stats_fetch_retry_irq(&lb_stats->syncp, start));
		bytes   += tbytes;
		packets += tpackets;
	}
	stats->rx_packets = packets;
	stats->tx_packets = packets;
	stats->rx_bytes   = bytes;
	stats->tx_bytes   = bytes;
}

static u32 always_on(struct net_device *dev)
{
	return 1;
}

static const struct ethtool_ops cas_vnet_ethtool_ops = {
	.get_link		= always_on,
	.get_ts_info		= ethtool_op_get_ts_info,
};

static int cas_vnet_dev_init(struct net_device *dev)
{
	dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;
	return 0;
}

static void cas_vnet_dev_free(struct net_device *dev)
{
	free_percpu(dev->lstats);
}

/*网络设备开启时会执行该函数*/
int cas_vnet_open(struct net_device *dev) {
#ifndef MAC_AUTO
    int i;
    for (i = 0; i < 6; i++) {
        dev->dev_addr[i] = 0xaa;
    }
#else
    random_ether_addr(dev->dev_addr);
#endif
    /*打开传输队列进行数据传输*/
    netif_start_queue(dev);         // 打开传输队列，这样才能传输数据，上层通过电梯算法等，进行调用
    printk("cas_vnet_dev_open\n\n\n");
    return 0;
}

/*关闭的时候，关闭队列*/
int cas_vnet_release(struct net_device *dev) {
    /*停止发送数据*/
    netif_stop_queue(dev);          // 关闭传输队列
    printk("cas_vnet_dev_release\n\n\n");
    return 0;
}

static const struct net_device_ops cas_vnet_ops = {
	.ndo_init        = cas_vnet_dev_init,
	.ndo_open		 = cas_vnet_open,		//打开网卡 对应ifconfig xx up
    .ndo_stop        = cas_vnet_release,    	//关闭网卡 对应ifconfig xx down
	.ndo_start_xmit  = cas_vnet_xmit,
	.ndo_get_stats64 = cas_vnet_get_stats64,
	//.ndo_set_mac_address = eth_mac_addr,
};

static void gen_lo_setup(struct net_device *dev,
			 unsigned int mtu,
			 const struct ethtool_ops *eth_ops,
			 const struct net_device_ops *dev_ops,
			 void (*dev_destructor)(struct net_device *dev))
{
	dev->mtu		= mtu;
	dev->hard_header_len	= ETH_HLEN;	/* 14	*/
	dev->min_header_len	= ETH_HLEN;	/* 14	*/
	dev->addr_len		= ETH_ALEN;	/* 6	*/
	//dev->type		= ARPHRD_LOOPBACK;	/* 0x0001*/
	//dev->flags		= IFF_LOOPBACK;
	// dev->priv_flags		|= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	netif_keep_dst(dev);
	// dev->hw_features	= NETIF_F_GSO_SOFTWARE;
	// dev->features		= NETIF_F_SG | NETIF_F_FRAGLIST
	// 	| NETIF_F_GSO_SOFTWARE
	// 	| NETIF_F_HW_CSUM
	// 	| NETIF_F_RXCSUM
	// 	| NETIF_F_SCTP_CRC
	// 	| NETIF_F_HIGHDMA
	// 	| NETIF_F_LLTX
	// 	| NETIF_F_NETNS_LOCAL;
	dev->netdev_ops		= dev_ops;
	dev->needs_free_netdev	= true;
	dev->priv_destructor	= dev_destructor;
}

/* The device is special. There is only one instance
 * per network namespace.
 */
static void cas_vnet_setup(struct net_device *dev)
{
	gen_lo_setup(dev, 1500, &cas_vnet_ethtool_ops,
		     &cas_vnet_ops, cas_vnet_dev_free);
}

/* Setup and register the device. */
static int __init cas_vnet_init(void)
{
	int err;
	printk("cas_vnet init\n\n");

	err = -ENOMEM;
	vnet_dev = alloc_netdev(0, Device_Name, NET_NAME_UNKNOWN, cas_vnet_setup);
	if (!vnet_dev)
		goto out;

	err = register_netdev(vnet_dev);
	if (err)
		goto out_free_netdev;

	//BUG_ON(vnet_dev->ifindex != LOOPBACK_IFINDEX);
	    
	printk("cas_vnet init ok\n\n");

	return 0;

out_free_netdev:
	free_netdev(vnet_dev);
out:
	panic("cas_vnet: Failed to register netdevice: %d\n", err);
	return err;
}


/*模块退出函数*/
static void __exit cas_vnet_exit(void) {
    printk("cas_vnet exit\n");
    unregister_netdev(vnet_dev);
	free_netdev(vnet_dev);
}


module_init(cas_vnet_init);
module_exit(cas_vnet_exit);
MODULE_LICENSE("GPL");


