#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
 

#define SRC_PORT            8888
#define DST_PORT            8888
#define SRC_IP              "192.168.0.101"
#define DST_IP              "192.168.0.102"
#define MAX_BUFFER          65535
#define MSG_STREAM          0

char buffer[MAX_BUFFER];

/*
struct sctp_sndrcvinfo {
    __u16 sinfo_stream;  //目标流
    __u16 sinfo_ssn;     //流序号
    __u16 sinfo_flags;   //标识符
    __u32 sinfo_ppid;    //有效负荷协议标识符
    __u32 sinfo_context; //出错返回值
    __u32 sinfo_timetolive;  //等待时间
    __u32 sinfo_tsn;         //传输序号
    __u32 sinfo_cumtsn;      //累积TSN
    sctp_assoc_t sinfo_assoc_id;  //关联ID
};
*/

int main() {
  int connSock, in, i, flags;
  struct sockaddr_in servaddr;
  struct sctp_status status;
  struct sctp_sndrcvinfo sndrcvinfo;
  struct sctp_event_subscribe events;
  struct sctp_initmsg initmsg;
 
  /* Create an SCTP TCP-Style Socket */
  connSock = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP );
 
  /* Specify that a maximum of 5 streams will be available per socket */
  memset( &initmsg, 0, sizeof(initmsg) );
  initmsg.sinit_num_ostreams = 5;
  initmsg.sinit_max_instreams = 5;
  initmsg.sinit_max_attempts = 4;
  setsockopt( connSock, IPPROTO_SCTP, SCTP_INITMSG,
                     &initmsg, sizeof(initmsg) );
 
  /* Specify the peer endpoint to which we'll connect */
  bzero( (void *)&servaddr, sizeof(servaddr) );
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(DST_PORT);
  servaddr.sin_addr.s_addr = inet_addr( DST_IP );
 
  /* Connect to the server */
  connect( connSock, (struct sockaddr *)&servaddr, sizeof(servaddr) );
 
  /* Enable receipt of SCTP Snd/Rcv Data via sctp_recvmsg */
  memset( (void *)&events, 0, sizeof(events) );
  events.sctp_data_io_event = 1;
  setsockopt( connSock, SOL_SCTP, SCTP_EVENTS,
                     (const void *)&events, sizeof(events) );
 
  /* Read and emit the status of the Socket (optional step) */
  in = sizeof(status);
  getsockopt( connSock, SOL_SCTP, SCTP_STATUS,
                     (void *)&status, (socklen_t *)&in );
 
  printf("assoc id = %d\n", status.sstat_assoc_id );
  printf("state = %d\n", status.sstat_state );
  printf("instrms = %d\n", status.sstat_instrms );
  printf("outstrms = %d\n", status.sstat_outstrms );
 
  /* Expect two messages from the peer */

  for (i = 0 ; i < 2 ; i++) {
 
/*
int sctp_recvmsg(int sd, void * msg, size_t len,
                struct sockaddr * from, socklen_t * fromlen,
                struct sctp_sndrcvinfo * sinfo, int * msg_flags);
    sd :    socket描述符
    msg：   消息指针
    len:    消息长度
    from:   源地址
    fromlen:    源地址长度
    sinfo:  消息的选项信息, 需要启用套接字选项 sctp_data_io_event
    msg_flags:  消息标识符
*/

    in = sctp_recvmsg( connSock, (void *)buffer, sizeof(buffer),
                        (struct sockaddr *)NULL, 0, &sndrcvinfo, &flags );
 
    if (in > 0) {
      buffer[in] = 0;
      if (sndrcvinfo.sinfo_stream == MSG_STREAM) {
        printf("(test msg) %s\n", buffer);
      }
    }
 
  }
 
  /* Close our socket and exit */
  close(connSock);
 
  return 0;
}
