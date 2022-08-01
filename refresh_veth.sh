#! /bin/bash

sudo modprobe -r myveth
cd ~/veth/
cp /mnt/hgfs/ubuntuShare/virtual-net-device/myveth.c ./
make
sudo cp myveth.ko /lib/modules/5.4.0-122-generic/
sudo depmod                         #刷新内核模块链接
sudo modprobe myveth                #加载内核模块链接
