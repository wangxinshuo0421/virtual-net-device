#include <stdio.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#include <net/if.h>		// 接口设计

#define NETWORK_ETH		"myveth0"
#define SRC_IP			"192.168.0.101"
#define SRC_PORT		6666
#define DST_IP			"192.168.0.102"
#define DST_PORT		6666

#define DATA_LEN 		1600

char msg[DATA_LEN] = {0};

int main(int argc, char *argv[]) {
	// 1.创建udp通信socket, 发送数据
	int udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(udp_socket_fd < 0 )
	{
		perror("creat socket fail\n");
		return -1;
	}
 
	// 绕过内核选路，指定发送网卡
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, NETWORK_ETH, strlen(NETWORK_ETH));
	setsockopt(udp_socket_fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr));

	//2.设置UDP的地址并绑定 
	struct sockaddr_in  local_addr = {0};
	local_addr.sin_family  = AF_INET; 			//使用IPv4协议
	local_addr.sin_port	= htons(SRC_PORT);   		//网络通信都使用大端格式
	local_addr.sin_addr.s_addr = inet_addr(SRC_IP);	// 绑定本地IP
 
	int ret = bind(udp_socket_fd, (struct sockaddr*)&local_addr, sizeof(local_addr));
	if(ret < 0) {
		perror("bind fail:");
		close(udp_socket_fd);
		return -1;
	}
	
	//设置目的IP地址
    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;//使用IPv4协议
    
	// 构造大数据包 
	for(int i = 0; i < DATA_LEN; i++)
		msg[i] = 'a';
	msg[DATA_LEN-1] = '\0';

	//循环发送消息 
	int cnt = 5;
	while(cnt)
	{
		// 构造大数据包 
		for(int i = 0; i < DATA_LEN; i++)
			msg[i] = 'a';
		msg[DATA_LEN-1] = '\0';
		//strcpy(msg, "1234567890");
		dest_addr.sin_port = htons(DST_PORT);//设置接收方端口号
		dest_addr.sin_addr.s_addr = inet_addr(DST_IP); //设置接收方IP 
		
		sendto(udp_socket_fd, msg, strlen(msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)); 
		printf("send msg : len: %lu, buf: %s",strlen(msg), msg);

		memset(msg,0,sizeof(msg));//清空存留消息
		cnt--;
	}
	
	//4 关闭通信socket
	close(udp_socket_fd);

	return 0;
}
