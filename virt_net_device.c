#include<linux/module.h>
#include<linux/sched.h>
#include<linux/kernel.h>
#include<linux/slab.h>
#include<linux/errno.h>
#include<linux/types.h>
#include<linux/interrupt.h>
#include<linux/in.h>
#include<linux/netdevice.h>
#include<linux/etherdevice.h>
#include<linux/ip.h>
//#include<linux/tcp.h>
#include<linux/skbuff.h>
#include<linux/if_ether.h>
#include<linux/in6.h>
#include<asm/uaccess.h>
#include<asm/checksum.h>
#include<linux/platform_device.h>

//#define  MAC_AUTO
static struct net_device *vir_net_devs;

struct vir_net_priv {
    struct net_device_stats stats;      //有用的统计信息
    int status;                         //网络设备的状态信息，是发完数据包，还是接收到网络数据包
    int rx_packetlen;                   //接收到的数据包长度
    u8 *rx_packetdata;                  //接收到的数据
    int tx_packetlen;                   //发送的数据包长度
    u8 *tx_packetdata;                  //发送的数据
    struct sk_buff *skb;                //socket buffer结构体，网络各层之间传送数据都是通过这个结构体来实现的
    spinlock_t lock;                    //自旋锁
};

/*网络设备开启时会执行该函数*/
int vir_net_open(struct net_device *dev) {
#ifndef MAC_AUTO
    int i;
    for (i=0; i<6; i++) {
        dev->dev_addr[i] = 0xaa;
    }
#else
    random_ether_addr(dev->dev_addr);
#endif
    /*打开传输队列进行数据传输*/
    netif_start_queue(dev);         // 打开传输队列，这样才能传输数据，上层通过电梯算法等，进行调用
    printk("vir_net_open\n");
    return 0;
}

/*关闭的时候，关闭队列*/
int vir_net_release(struct net_device *dev) {
    /*停止发送数据*/
    netif_stop_queue(dev);          // 关闭传输队列
    printk("vir_net_release\n");
    return 0;
}

/*接包函数,有数据过来时，中断执行*/
void vir_net_rx(struct net_device *pdev, int len, unsigned char *buf) {
    struct sk_buff *skb;
    struct vir_net_priv *priv = (struct vir_net_priv *) pdev->ml_priv;
    skb = dev_alloc_skb(len+2);//分配一个socket buffer,并且初始化skb->data,skb->tail和skb->head
    if(!skb) {
        printk("gecnet rx: low on mem - packet dropped\n");
        priv->stats.rx_dropped++;
        return;
    }
    skb_reserve(skb, 2); /* align IP on 16B boundary */ 
    memcpy(skb_put(skb, len), buf, len);//skb_put是把数据写入到socket buffer
    /* Write metadata, and then pass to the receive level */
    skb->dev = pdev;
    skb->protocol = eth_type_trans(skb, pdev);//返回的是协议号
    skb->ip_summed = CHECKSUM_UNNECESSARY; //此处不校验
    priv->stats.rx_packets++;//接收到包的个数＋1

    priv->stats.rx_bytes += len;//接收到包的长度
    printk("vir_net_rx  protocol num: %d\n", skb->protocol);
    netif_rx(skb);//通知内核已经接收到包，并且封装成socket buffer传到上层
    return;
}

/*模拟硬件发送数据*/
void vir_net_hw_tx(char *buf, int len, struct net_device *dev) {
    struct net_device *dest;//目标设备结构体，net_device存储一个网络接口的重要信息，是网络驱动程序的核心
    struct vir_net_priv *priv;

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        printk("vir_net: packet too short (%i octets)\n", len);
        return;
    }
    dest = vir_net_devs;
    priv = (struct vir_net_priv *)dest->ml_priv;
    priv->rx_packetlen = len;
    priv->rx_packetdata = buf;

    //printk("vir_net_hw_tx\n");
    dev_kfree_skb(priv->skb);
}


/*发包函数, 上层有数据发送时，该函数会被调用*/
int vir_net_tx(struct sk_buff *skb, struct net_device *pdev) {
    int len;
    char *data;
    struct vir_net_priv *priv = (struct vir_net_priv *)pdev->ml_priv;
    if(skb == NULL) {
        printk("net_device = %p, skb = %p\n", pdev, skb);
        return 0;
    }
    /*ETH_ZLEN是所发的最小数据包的长度*/
    len = skb->len < ETH_ZLEN ? ETH_ZLEN : skb->len;
    /*将要发送的数据包中数据部分*/
    data = skb->data;
    priv->skb = skb;
    /*调用硬件接口进行数据的发送*/
    vir_net_hw_tx(data, len, pdev);
    printk("vir_net_tx, protocol num = %d\n", skb->protocol);
    return 0; 
}

/*设备初始化函数*/
int vir_net_device_init(struct net_device *pdev) {
    /*填充一些以太网中的设备结构体的项*/
    ether_setup(pdev);
    /*keep the default flags, just add NOARP */
    pdev->flags |= IFF_NOARP;
    /*为priv分配内存*/
    pdev->ml_priv = kmalloc(sizeof(struct vir_net_priv), GFP_KERNEL);
    if (pdev->ml_priv == NULL){
        return -ENOMEM;
    }
    memset(pdev->ml_priv, 0, sizeof(struct vir_net_priv));
    spin_lock_init(&((struct vir_net_priv *)pdev->ml_priv)->lock);
    printk("vir_net_device_init, pdev = %p\n", pdev);
    return 0;
}

int vir_net_void_tx(struct sk_buff *skb, struct net_device *pdev) {
    netif_rx(skb);
    printk("test tx!\n\n");
    return 0;
}

/*结构体填充*/
static const struct net_device_ops vir_net_netdev_ops = {
    .ndo_open       = vir_net_open,       //打开网卡 对应ifconfig xx up
    .ndo_stop       = vir_net_release,    //关闭网卡 对应ifconfig xx down
    .ndo_start_xmit = vir_net_void_tx,         //开启数据包传输(对应上层要发送数据时)
    .ndo_init       = vir_net_device_init,       //初始化网卡硬件
};


/**/
static void vir_plat_net_release(struct device *pdev) {
    printk("vir_plat_net_release, pdev = %p\n", pdev);
}


/*匹配*/
static int vir_net_probe(struct platform_device *pdev) {
    int result = 0;
    /*vir_net_devs结构体相当于一个虚拟的网络设备*/
    vir_net_devs = alloc_etherdev(sizeof(struct net_device));
    vir_net_devs->netdev_ops = &vir_net_netdev_ops;
    strcpy(vir_net_devs->name, "vnet0");
    /*上面填充了3项，如果是真实的网卡会填充更多，然后
    使用register_netdev进行注册，net/core,注册好了以后
    内核当中就会有这个设备了，当这个网络设备up以后就会进入open函数*/
    if ((result = register_netdev(vir_net_devs))) {
        printk("vir_net: error %i registering device \"%s\"\n", result, vir_net_devs->name);
    }
    printk("vir_net_probe, pdev = %p\n", pdev);
    return 0;
}

/*设备移除函数*/
static int  vir_net_remove(struct platform_device *pdev) {
    kfree(vir_net_devs->ml_priv);
    unregister_netdev(vir_net_devs);
    return 0;
}

/*结构体填充*/
static struct platform_device vir_net= {
    .name = "vir_net",
    .id   = -1,
    .dev  = {
    .release = vir_plat_net_release,
    },
};

/*结构体填充*/
static struct platform_driver vir_net_driver = {
    .probe  = vir_net_probe,
    .remove  = vir_net_remove,
    .driver  = {
    .name = "vir_net",    /*这里的name和上面那个结构体的name如果匹配就会执行probe函数*/
    .owner = THIS_MODULE,
    },
};

/*模块入口函数*/
static int __init vir_net_init(void) {
    printk("vir_net_init\n");
    platform_device_register(&vir_net);
    return platform_driver_register(& vir_net_driver);
}

/*模块退出函数*/
static void __exit vir_net_exit(void) {
    printk("vir_net_exit\n");
    platform_driver_unregister(&vir_net_driver);
    platform_device_unregister(&vir_net);
}



module_init(vir_net_init);
module_exit(vir_net_exit);
MODULE_LICENSE("GPL");
