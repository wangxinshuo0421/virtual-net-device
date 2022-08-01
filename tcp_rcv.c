// server.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define SRC_PORT            8888
#define DST_PORT            8888
#define SRC_IP              "192.168.0.102"
#define DST_IP              "192.168.0.101"
#define MAX_RCV_BUFF_SIZE   65535

char buf[MAX_RCV_BUFF_SIZE];

int main() {
    // 1. 创建监听的套接字
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd == -1) {
        perror("socket create error\n");
        exit(0);
    }
    // 2. 将socket()返回值和本地的IP端口绑定到一起
    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(SRC_PORT);   // 大端端口
    // INADDR_ANY代表本机的所有IP, 假设有三个网卡就有三个IP地址
    // 这个宏可以代表任意一个IP地址
    // 这个宏一般用于本地的绑定操作
    local_addr.sin_addr.s_addr = inet_addr(SRC_IP);  
    int ret = bind(lfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret == -1) {
        perror("bind error\n");
        exit(0);
    }
    // 3. 设置监听
    ret = listen(lfd, 128);
    if(ret == -1) {
        perror("listen error\n");
        exit(0);
    }
    printf("waiting client connect...\n");

    // 4. 阻塞等待并接受客户端连接
    struct sockaddr_in clien_addr;
    int clien_len = sizeof(clien_addr);
    int cfd = accept(lfd, (struct sockaddr*)&clien_addr, &clien_len);
    if(cfd == -1) {
        perror("accept error\n");
        exit(0);
    }
    // 打印客户端的地址信息
    char ip[24] = {0};
    printf("客户端的IP地址: %s, 端口: %d\n",
           inet_ntop(AF_INET, &clien_addr.sin_addr.s_addr, ip, sizeof(ip)),
           ntohs(clien_addr.sin_port));

    // 5. 和客户端通信
    while(1) {
        // 接收数据
        memset(buf, 0, sizeof(buf));
        int len = read(cfd, buf, sizeof(buf));
        if(len > 0) {
            printf("rcv: %s\n", buf);
            //write(cfd, buf, len);
        }
        else if(len  == 0) {
            printf("客户端断开了连接...\n");
            break;
        }
        else {
            perror("read error\n");
            break;
        }
    }

    close(cfd);
    close(lfd);

    return 0;
}

