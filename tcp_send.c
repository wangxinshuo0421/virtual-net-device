
// client.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define SRC_PORT            8888
#define DST_PORT            8888
#define SRC_IP              "192.168.0.101"
#define DST_IP              "192.168.0.102"
#define MAX_SEND_BUFF_SIZE  65535

char buf[MAX_SEND_BUFF_SIZE];

int main() {
    // 1. 创建通信的套接字
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1) {
        perror("socket create error\n");
        exit(0);
    }

    // 2. 连接服务器
    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(DST_PORT);   // 大端端口
    inet_pton(AF_INET, DST_IP, &dst_addr.sin_addr.s_addr);

    int ret = connect(fd, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    if(ret == -1) {
        perror("connect error \n");
        exit(0);
    }

    // 3. 和服务器端通信
    int cnt = 3;
    int data_len = 5000;
    for(int i = 0; i < data_len; i++) buf[i] = 'a';
    buf[data_len] = '\0';
    while(cnt) {
        // 发送数据
        write(fd, buf, strlen(buf)+1);
        usleep(200);   // 每隔200us发送一条数据
        cnt--;
    }

    close(fd);

    return 0;
}

