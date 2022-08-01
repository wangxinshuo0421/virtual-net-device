#include <stdio.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#define SRC_IP          "192.168.0.102"
#define SRC_PORT        6666
 
int main(int argc,char *argv[]) {
	
	int udp_socket_fd = socket(AF_INET,SOCK_DGRAM,0);   // 1.创建udp通信socket  
	
	if(udp_socket_fd < 0 ) {
		perror("creat socket fail\n");
		return -1;
	}
 
	struct sockaddr_in  local_addr = {0};                   //2.设置UDP的地址并绑定 
	local_addr.sin_family  = AF_INET;                       //使用IPv4协议
	local_addr.sin_port	= htons(SRC_PORT);                      //网络通信都使用大端格式
	local_addr.sin_addr.s_addr = inet_addr(SRC_IP);  //让系统检测本地网卡，自动绑定本地IP
 
	int ret = bind(udp_socket_fd, (struct sockaddr*)&local_addr, sizeof(local_addr));
	
	if(ret < 0) {
		perror("bind fail:");
		close(udp_socket_fd);
		return -1;
	} else {
		printf("recv ready!!!\n");
	}
 
	struct sockaddr_in  src_addr = {0};     // 用来存放对方(信息的发送方)的IP地址信息
	int len = sizeof(src_addr);	            // 地址信息的大小
	char buf[2500] = {0};                   // 消息缓冲区
	
	//3 循环接收客户发送过来的数据  
	while(1) {
		ret = recvfrom(udp_socket_fd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &len);
		
		if(ret == -1) {
			break;
		}
		
		printf("[%s : %d] : ",inet_ntoa(src_addr.sin_addr),ntohs(src_addr.sin_port));//打印消息发送方的ip与端口号
		printf("len = %lu, buf = %s\n",strlen(buf), buf);
		
		if(strcmp(buf, "exit") == 0) {
			break;
		}
		memset(buf, 0, sizeof(buf));//清空存留消息
	}
	
	close(udp_socket_fd);//4 关闭通信socket
	
	return 0;
}
