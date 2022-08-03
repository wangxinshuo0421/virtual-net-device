#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/veth.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/ptr_ring.h>
#include <linux/bpf_trace.h>
#include <linux/net_tstamp.h>

/* 卸载功能头文件*/
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/sctp.h>
#include <net/sctp/checksum.h>


#define DRV_NAME	"myveth"
#define DRV_VERSION	"1.0"

#define VETH_RING_SIZE		256

struct veth_rq_stats {
	u64			xdp_packets;
	u64			xdp_bytes;
	u64			xdp_drops;
	struct u64_stats_sync	syncp;
};

struct veth_rq {
	struct napi_struct		napi;
	struct net_device		*dev;
	struct veth_rq_stats	stats;
	struct ptr_ring			ring;
	bool					rx_notify_masked;
	struct bpf_prog __rcu	*prog;
};

struct veth_priv {
	struct net_device __rcu	*peer;
	atomic64_t				dropped;
	struct veth_rq			*rq;
	struct bpf_prog			*_prog;
	unsigned int			requested_headroom;
};

/*
 * ethtool interface
 */

struct veth_q_stat_desc {
	char	desc[ETH_GSTRING_LEN];
	size_t	offset;
};

#define VETH_RQ_STAT(m)	offsetof(struct veth_rq_stats, m)

#define VETH_RQ_STATS_LEN	3

static struct {
	const char string[ETH_GSTRING_LEN];
} ethtool_stats_keys[] = {
	{ "peer_ifindex" },
};

static int veth_get_link_ksettings(struct net_device *dev,
				   struct ethtool_link_ksettings *cmd)
{
	cmd->base.speed		= SPEED_10000;
	cmd->base.duplex	= DUPLEX_FULL;
	cmd->base.port		= PORT_TP;
	cmd->base.autoneg	= AUTONEG_DISABLE;
	return 0;
}

static void veth_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static int veth_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stats_keys) +
		       VETH_RQ_STATS_LEN * dev->real_num_rx_queues;
	default:
		return -EOPNOTSUPP;
	}
}

static void veth_get_ethtool_stats(struct net_device *dev,
		struct ethtool_stats *stats, u64 *data)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);
	int i, j, idx;

	data[0] = peer ? peer->ifindex : 0;
	idx = 1;

}

static const struct ethtool_ops veth_ethtool_ops = {
	.get_drvinfo		= veth_get_drvinfo,
	.get_link			= ethtool_op_get_link,
	.get_sset_count		= veth_get_sset_count,
	.get_ethtool_stats	= veth_get_ethtool_stats,
	.get_link_ksettings	= veth_get_link_ksettings,
	.get_ts_info		= ethtool_op_get_ts_info,
};

static int veth_forward_skb(struct net_device *dev, struct sk_buff *skb,
			    struct veth_rq *rq, bool xdp)
{
	return __dev_forward_skb(dev, skb) ?: xdp ?	0 :netif_rx(skb);
}
//! @param buff The UDP packet.
//! @param len The UDP packet length.
//! @param src_addr The IP source address (in network format).
//! @param dest_addr The IP destination address (in network format).
//! @return The result of the checksum.
uint16_t udp_checksum(const void *buff, uint16_t len, uint32_t src_addr, uint32_t dest_addr)
{
        const uint16_t *buf = buff;
        uint16_t *ip_src = (void *)&src_addr, *ip_dst = (void *)&dest_addr;
        uint32_t sum;
        uint16_t length = len;
  
        // Calculate the sum                                            //
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }
  
        if ( len & 1 )
                // Add the padding if the packet lenght is odd          //
                sum += *((uint8_t *)buf);
  
        // Add the pseudo-header                                        //
        sum += *(ip_src++);
        sum += *ip_src;
  
        sum += *(ip_dst++);
        sum += *ip_dst;
  
        sum += htons(IPPROTO_UDP);
        sum += htons(length);
  
        // Add the carries                                              //
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);
  
        // Return the one's complement of sum                           //
        return ( (uint16_t)(~sum)  );
}
 
 
/*
 * 使用方式
 * udph->check = 0;
 * udph->check = udp_checksum(udph, ntohs(udph->len), iph->saddr, iph->daddr);
 */

static netdev_tx_t veth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct veth_priv *rcv_priv, *priv = netdev_priv(dev);
	struct veth_rq *rq = NULL;
	struct net_device *rcv;
	int length = skb->len;
	bool rcv_xdp = false;
	int rxq;

	/* Only one fragment on the socket. */
	if (!skb_has_frag_list(skb)) {
		struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
		/* ip checksum offload */
		if (iph->check == 0) {
			uint16_t ipCksum = ip_fast_csum((unsigned char *)iph, iph->ihl);
			printk("ip offload now ip_fast_csum = %u\n", ipCksum);
			iph->check = ipCksum;
		} else printk("ip not offload; ip cksum = %u\n", iph->check);
		
		/* udp checksum offload */
		if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph = (struct udphdr *)skb_transport_header(skb);
			if (udph->check == 0) {
				uint16_t udpCksum = udp_checksum(udph, ntohs(udph->len), iph->saddr, iph->daddr);
				printk("udp cksum offload now cksum = %u; [port: %d] ", udpCksum, ntohs(udph->source));
				udph->check = udpCksum;
			} else printk("udp not offload; udp cksum = %u\n", udph->check);
		}

		/* sctp checksum offload */
		if (iph->protocol == IPPROTO_SCTP) {
			struct sctphdr *sctph = (struct sctphdr *)skb_transport_header(skb);
			if (sctph->checksum == 0) {
				sctph->checksum = sctp_compute_cksum(skb, skb_network_offset(skb));
			}
		}
	} else {
		struct sk_buff *frags;
		struct iphdr *iph = (struct iphdr *)skb_network_header(skb);

		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		/* sctp checksum offload */
		if (iph->protocol == IPPROTO_SCTP) {
			struct sctphdr *sctph = (struct sctphdr *)skb_transport_header(skb);
			if (sctph->checksum == 0) {
				sctph->checksum = sctp_compute_cksum(skb, skb_network_offset(skb));
			}
		}

	}

	rcu_read_lock();
	rcv = rcu_dereference(priv->peer);
	if (unlikely(!rcv) || !pskb_may_pull(skb, ETH_HLEN)) {
		kfree_skb(skb);
		goto drop;
	}
    //printk("i transmit a packet\n");

	rcv_priv = netdev_priv(rcv);
	rxq = skb_get_queue_mapping(skb);
	if (rxq < rcv->real_num_rx_queues) {
		rq = &rcv_priv->rq[rxq];
		rcv_xdp = rcu_access_pointer(rq->prog);
	}

	skb_tx_timestamp(skb);
	if (likely(veth_forward_skb(rcv, skb, rq, rcv_xdp) == NET_RX_SUCCESS)) {
		if (!rcv_xdp) {
			struct pcpu_lstats *stats = this_cpu_ptr(dev->lstats);

			u64_stats_update_begin(&stats->syncp);
			stats->bytes += length;
			stats->packets++;
			u64_stats_update_end(&stats->syncp);
		}
	} else {
drop:
		atomic64_inc(&priv->dropped);
	}

	rcu_read_unlock();

	return NETDEV_TX_OK;
}

static u64 veth_stats_tx(struct pcpu_lstats *result, struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int cpu;

	result->packets = 0;
	result->bytes = 0;
	for_each_possible_cpu(cpu) {
		struct pcpu_lstats *stats = per_cpu_ptr(dev->lstats, cpu);
		u64 packets, bytes;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			packets = stats->packets;
			bytes = stats->bytes;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));
		result->packets += packets;
		result->bytes += bytes;
	}
	return atomic64_read(&priv->dropped);
}


static void veth_get_stats64(struct net_device *dev,
			     struct rtnl_link_stats64 *tot)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	struct pcpu_lstats tx;

	tot->tx_dropped = veth_stats_tx(&tx, dev);
	tot->tx_bytes = tx.bytes;
	tot->tx_packets = tx.packets;

	tot->rx_dropped = 0;
	tot->rx_bytes = 0;
	tot->rx_packets = 0;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (peer) {
		tot->rx_dropped += veth_stats_tx(&tx, peer);
		tot->rx_bytes += tx.bytes;
		tot->rx_packets += tx.packets;

		tot->tx_bytes += 0;
		tot->tx_packets += 0;
	}
	rcu_read_unlock();
}

/* fake multicast ability */
static void veth_set_multicast_list(struct net_device *dev)
{
}

static struct sk_buff *veth_build_skb(void *head, int headroom, int len,
				      int buflen)
{
	struct sk_buff *skb;

	if (!buflen) {
		buflen = SKB_DATA_ALIGN(headroom + len) +
			 SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	}
	skb = build_skb(head, buflen);
	if (!skb)
		return NULL;

	skb_reserve(skb, headroom);
	skb_put(skb, len);

	return skb;
}

static int veth_select_rxq(struct net_device *dev)
{
	return smp_processor_id() % dev->real_num_rx_queues;
}

static void veth_ptr_free(void *ptr)
{
		kfree_skb(ptr);
}
static int veth_poll(struct napi_struct *napi, int budget){return 1;}

static int veth_napi_add(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int err, i;

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		err = ptr_ring_init(&rq->ring, VETH_RING_SIZE, GFP_KERNEL);
		if (err)
			goto err_ring;
	}

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		netif_napi_add(dev, &rq->napi, veth_poll, NAPI_POLL_WEIGHT);
		napi_enable(&rq->napi);
	}

	return 0;
err_ring:
	for (i--; i >= 0; i--)
		ptr_ring_cleanup(&priv->rq[i].ring, veth_ptr_free);

	return err;
}

static void veth_napi_del(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		napi_disable(&rq->napi);
		napi_hash_del(&rq->napi);
	}
	synchronize_net();

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		netif_napi_del(&rq->napi);
		rq->rx_notify_masked = false;
		ptr_ring_cleanup(&rq->ring, veth_ptr_free);
	}
}


static int veth_open(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);
	int err;

	if (!peer)
		return -ENOTCONN;

	if (peer->flags & IFF_UP) {
		netif_carrier_on(dev);
		netif_carrier_on(peer);
	}

	return 0;
}

static int veth_close(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	netif_carrier_off(dev);
	if (peer)
		netif_carrier_off(peer);

	return 0;
}

static int is_valid_veth_mtu(int mtu)
{
	return mtu >= ETH_MIN_MTU && mtu <= ETH_MAX_MTU;
}

static int veth_alloc_queues(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int i;

	priv->rq = kcalloc(dev->num_rx_queues, sizeof(*priv->rq), GFP_KERNEL);
	if (!priv->rq)
		return -ENOMEM;

	for (i = 0; i < dev->num_rx_queues; i++) {
		priv->rq[i].dev = dev;
		u64_stats_init(&priv->rq[i].stats.syncp);
	}

	return 0;
}

static void veth_free_queues(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);

	kfree(priv->rq);
}

static int veth_dev_init(struct net_device *dev)
{
	int err;

	dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;

	err = veth_alloc_queues(dev);
	if (err) {
		free_percpu(dev->lstats);
		return err;
	}

	return 0;
}

static void veth_dev_free(struct net_device *dev)
{
	veth_free_queues(dev);
	free_percpu(dev->lstats);
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void veth_poll_controller(struct net_device *dev)
{
	/* veth only receives frames when its peer sends one
	 * Since it has nothing to do with disabling irqs, we are guaranteed
	 * never to have pending data when we poll for it so
	 * there is nothing to do here.
	 *
	 * We need this though so netpoll recognizes us as an interface that
	 * supports polling, which enables bridge devices in virt setups to
	 * still use netconsole
	 */
}
#endif	/* CONFIG_NET_POLL_CONTROLLER */

static int veth_get_iflink(const struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	int iflink;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	iflink = peer ? peer->ifindex : 0;
	rcu_read_unlock();

	return iflink;
}

static netdev_features_t veth_fix_features(struct net_device *dev,
					   netdev_features_t features)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer;

	peer = rtnl_dereference(priv->peer);
	if (peer) {
		struct veth_priv *peer_priv = netdev_priv(peer);

		if (peer_priv->_prog)
			features &= ~NETIF_F_GSO_SOFTWARE;
	}

	return features;
}

static void veth_set_rx_headroom(struct net_device *dev, int new_hr)
{
	struct veth_priv *peer_priv, *priv = netdev_priv(dev);
	struct net_device *peer;

	if (new_hr < 0)
		new_hr = 0;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (unlikely(!peer))
		goto out;

	peer_priv = netdev_priv(peer);
	priv->requested_headroom = new_hr;
	new_hr = max(priv->requested_headroom, peer_priv->requested_headroom);
	dev->needed_headroom = new_hr;
	peer->needed_headroom = new_hr;

out:
	rcu_read_unlock();
}



static const struct net_device_ops veth_netdev_ops = {
	.ndo_init            	= veth_dev_init,
	.ndo_open            	= veth_open,
	.ndo_stop            	= veth_close,
	.ndo_start_xmit      	= veth_xmit,
	.ndo_get_stats64     	= veth_get_stats64,
	.ndo_set_rx_mode     	= veth_set_multicast_list,
	.ndo_set_mac_address 	= eth_mac_addr,
	.ndo_get_iflink		 	= veth_get_iflink,
	.ndo_fix_features	 	= veth_fix_features,
	.ndo_features_check	 	= passthru_features_check,
	.ndo_set_rx_headroom	= veth_set_rx_headroom,
};

#define VETH_FEATURES ( NETIF_F_IP_CSUM | NETIF_F_FRAGLIST | NETIF_F_HW_CSUM | \
		       			NETIF_F_RXCSUM | NETIF_F_SCTP_CRC | NETIF_F_HIGHDMA | \
		       			NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL |NETIF_F_SG )

static void veth_setup(struct net_device *dev) {
	ether_setup(dev);
	
	dev->netdev_ops = &veth_netdev_ops;
	dev->ethtool_ops = &veth_ethtool_ops;
	dev->features |= NETIF_F_LLTX;
	dev->features |= VETH_FEATURES;

	dev->needs_free_netdev = true;
	dev->priv_destructor = veth_dev_free;
	dev->max_mtu = ETH_MAX_MTU;

	dev->hw_features = VETH_FEATURES;
	dev->hw_enc_features = VETH_FEATURES;
	dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
}

/*
 * netlink interface
 */

static int veth_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (tb[IFLA_MTU]) {
		if (!is_valid_veth_mtu(nla_get_u32(tb[IFLA_MTU])))
			return -EINVAL;
	}
	return 0;
}

static struct rtnl_link_ops veth_link_ops;

static int veth_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	int err;
	struct net_device *peer;
	struct veth_priv *priv;
	char ifname[IFNAMSIZ];
	struct nlattr *peer_tb[IFLA_MAX + 1], **tbp;
	unsigned char name_assign_type;
	struct ifinfomsg *ifmp;
	struct net *net;

	/*
	 * create and register peer first
	 */
	if (data != NULL && data[VETH_INFO_PEER] != NULL) {
		struct nlattr *nla_peer;

		nla_peer = data[VETH_INFO_PEER];
		ifmp = nla_data(nla_peer);
		err = rtnl_nla_parse_ifla(peer_tb,
					  nla_data(nla_peer) + sizeof(struct ifinfomsg),
					  nla_len(nla_peer) - sizeof(struct ifinfomsg),
					  NULL);
		if (err < 0)
			return err;

		err = veth_validate(peer_tb, NULL, extack);
		if (err < 0)
			return err;

		tbp = peer_tb;
	} else {
		ifmp = NULL;
		tbp = tb;
	}

	if (ifmp && tbp[IFLA_IFNAME]) {
		nla_strlcpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
		name_assign_type = NET_NAME_USER;
	} else {
		snprintf(ifname, IFNAMSIZ, DRV_NAME "%%d");
		name_assign_type = NET_NAME_ENUM;
	}

	net = rtnl_link_get_net(src_net, tbp);
	if (IS_ERR(net))
		return PTR_ERR(net);

	peer = rtnl_create_link(net, ifname, name_assign_type,
				&veth_link_ops, tbp, extack);
	if (IS_ERR(peer)) {
		put_net(net);
		return PTR_ERR(peer);
	}

	if (!ifmp || !tbp[IFLA_ADDRESS])
		eth_hw_addr_random(peer);

	if (ifmp && (dev->ifindex != 0))
		peer->ifindex = ifmp->ifi_index;

	peer->gso_max_size = dev->gso_max_size;
	peer->gso_max_segs = dev->gso_max_segs;

	err = register_netdevice(peer);
	put_net(net);
	net = NULL;
	if (err < 0)
		goto err_register_peer;

	netif_carrier_off(peer);

	err = rtnl_configure_link(peer, ifmp);
	if (err < 0)
		goto err_configure_peer;

	/*
	 * register dev last
	 *
	 * note, that since we've registered new device the dev's name
	 * should be re-allocated
	 */

	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strlcpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err_register_dev;

	netif_carrier_off(dev);

	/*
	 * tie the deviced together
	 */

	priv = netdev_priv(dev);
	rcu_assign_pointer(priv->peer, peer);

	priv = netdev_priv(peer);
	rcu_assign_pointer(priv->peer, dev);

	return 0;

err_register_dev:
	/* nothing to do */
err_configure_peer:
	unregister_netdevice(peer);
	return err;

err_register_peer:
	free_netdev(peer);
	return err;
}

static void veth_dellink(struct net_device *dev, struct list_head *head)
{
	struct veth_priv *priv;
	struct net_device *peer;

	priv = netdev_priv(dev);
	peer = rtnl_dereference(priv->peer);

	/* Note : dellink() is called from default_device_exit_batch(),
	 * before a rcu_synchronize() point. The devices are guaranteed
	 * not being freed before one RCU grace period.
	 */
	RCU_INIT_POINTER(priv->peer, NULL);
	unregister_netdevice_queue(dev, head);

	if (peer) {
		priv = netdev_priv(peer);
		RCU_INIT_POINTER(priv->peer, NULL);
		unregister_netdevice_queue(peer, head);
	}
}

static const struct nla_policy veth_policy[VETH_INFO_MAX + 1] = {
	[VETH_INFO_PEER]	= { .len = sizeof(struct ifinfomsg) },
};

static struct net *veth_get_link_net(const struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	return peer ? dev_net(peer) : dev_net(dev);
}

static struct rtnl_link_ops veth_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct veth_priv),
	.setup		= veth_setup,
	.validate	= veth_validate,
	.newlink	= veth_newlink,
	.dellink	= veth_dellink,
	.policy		= veth_policy,
	.maxtype	= VETH_INFO_MAX,
	.get_link_net	= veth_get_link_net,
};

/*
 * init/fini
 */

static __init int veth_init(void)
{
	return rtnl_link_register(&veth_link_ops);
}

static __exit void veth_exit(void)
{
	rtnl_link_unregister(&veth_link_ops);
}

module_init(veth_init);
module_exit(veth_exit);

MODULE_DESCRIPTION("Virtual Ethernet Network Card");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
