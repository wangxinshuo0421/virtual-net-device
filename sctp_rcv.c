#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

 
#define MAX_BUFFER          65535
#define SRC_PORT            8888
#define DST_PORT            8888
#define SRC_IP              "192.168.0.102"
#define DST_IP              "192.168.0.101"
#define MSG_STREAM          0

char buffer[MAX_BUFFER];

int main() {
  int listenSock, connSock, ret;
  struct sockaddr_in servaddr;
  struct sctp_initmsg initmsg;
  time_t currentTime;
 
  /* Create SCTP TCP-Style Socket */
  listenSock = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP );
 
  /* Accept connections from any interface */
  bzero( (void *)&servaddr, sizeof(servaddr) );
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(SRC_IP);
  servaddr.sin_port = htons(SRC_PORT);
 
  ret = bind( listenSock, (struct sockaddr *)&servaddr, sizeof(servaddr) );
 
  /* Specify that a maximum of 5 streams will be available per socket */
  memset( &initmsg, 0, sizeof(initmsg) );
  initmsg.sinit_num_ostreams = 5;
  initmsg.sinit_max_instreams = 5;
  initmsg.sinit_max_attempts = 4;
  ret = setsockopt( listenSock, IPPROTO_SCTP, SCTP_INITMSG,
                     &initmsg, sizeof(initmsg) );
 
  /* Place the server socket into the listening state */
  listen( listenSock, 5 );
 
  /* Server loop... */
  while( 1 ) {
 
    /* Await a new client connection */
    printf("Awaiting a new connection\n");
    connSock = accept( listenSock, (struct sockaddr *)NULL, (int *)NULL );
 
    /* New client socket has connected */
 
    /* Grab the current time */
    currentTime = time(NULL);
 
/*
int sctp_sendmsg(int sd, const void * msg, size_t len,
                struct sockaddr *to, socklen_t tolen,
                uint32_t ppid, uint32_t flags,
                uint16_t stream_no, uint32_t timetolive,
                uint32_t context);
    sd :    socket描述符
    msg：   消息指针
    len:    消息长度
    to：    目的地址
    tolen： 目的地址长度
    ppid:   应用指定的有效负荷协议标识符
    flags:  发送标识符
    stream_no： 目标流
    timetolive: 等待时间，此值为消息未能成功发送到对等方的情况下消息过期之前可以等待的时间段，以毫秒为单位。
    context:    出错返回值，如果在发送消息时出现错误，则返回此值。
*/

    /* Send Test Msg on stream 0 (MSG_STREAM) */
    int data_len = 2000;
    for(int i = 0; i < data_len; i++)
      buffer[i] = 'a';
    buffer[data_len] = '\0';
    ret = sctp_sendmsg( connSock, (void *)buffer, (size_t)strlen(buffer),
                         NULL, 0, 0, 0, MSG_STREAM, 0, 0 );
 
 
    /* Close the client connection */
    close( connSock );
 
  }
 
  return 0;
}
