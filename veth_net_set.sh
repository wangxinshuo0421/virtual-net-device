#! /bin/bash

# 创建2个网络容器
sudo ip netns add net0
sudo ip netns add net1

# 创建2对儿 veth 出来
sudo ip link add myveth0_p type myveth
sudo ip link add myveth1_p type myveth

# 把两个网卡的其中的一头 veth1 放到这个新的 netns 中。
sudo ip link set myveth0 netns net0
sudo ip link set myveth1 netns net1

# 为其配置上 ip，并把它启动起来
sudo ip netns exec net0 ip addr add 192.168.0.101/24 dev myveth0
sudo ip netns exec net0 ip link set myveth0 up
sudo ip netns exec net1 ip addr add 192.168.0.102/24 dev myveth1
sudo ip netns exec net1 ip link set myveth1 up

# 创建一个 bridge 设备
sudo brctl addbr br0

# 两对儿 veth 中剩下的两头“插”到 bridge 上来。
sudo ip link set dev myveth0_p master br0
sudo ip link set dev myveth1_p master br0

# 为 bridge 配置上 IP
sudo ip addr add 192.168.0.100/24 dev br0

# 把 bridge 以及插在其上的 veth 启动起来
sudo ip link set myveth0_p up
sudo ip link set myveth1_p up
sudo ip link set br0 up

# sudo echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
# sudo echo 0 > /proc/sys/net/ipv4/conf/myveth0/rp_filter
# sudo echo 0 > /proc/sys/net/ipv4/conf/myveth1/rp_filter
# sudo echo 1 > /proc/sys/net/ipv4/conf/myveth1/accept_local
# sudo echo 1 > /proc/sys/net/ipv4/conf/myveth0/accept_local
