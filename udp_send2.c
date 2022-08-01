#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <net/if.h>
#include <stdio.h>
 
#define DEST_IP "192.168.0.102"
#define DEST_PORT 6666
#define SRC_IP "192.168.0.101"
#define SRC_PORT 6666
#define TEST_MESSAGE "This test udp message!"
#define NETWORK_CAP "myveth0"
unsigned int m_OutSocket;
struct sockaddr_in m_SocketOut;
 
typedef struct stuIPHEADER
{
        unsigned char h_lenver;			// 8bit 4bit版本 + 4bit首部长度
        						// (h_lenver &0xf) * 4
        unsigned char tos;				// 8bit 服务类型
        unsigned short total_len;		// 16bit 总长度(字节数)
        unsigned short ident;			// 16bit 标识
        unsigned short frag_and_flags;	// 16bit 3bit标志 + 13bit片偏移
        unsigned char ttl;				// 8bit 生存时间(TTL)
        unsigned char proto;			// 8bit 上层协议
        unsigned short checksum;		// 16bit 检验和
        unsigned int sourceIP;			// 32bit 源IP地址
        unsigned int destIP;			// 32bit 目的IP地址
}IPHEADER, *LPIPHEADER;
 
typedef struct _UDP_HEADER {
    unsigned short    nSourPort ;            // 源端口号
    unsigned short    nDestPort ;            // 目的端口号
    unsigned short    nLength ;				 // 数据包长度
    unsigned short    nCheckSum ;            // 校验和
} UDP_HEADER, *PUDP_HEADER ;
 
typedef struct _PSD_HEADER{
	unsigned long         saddr;	//源IP地址               
	unsigned long         daddr;	//目的IP地址
	char                  mbz;		//置空(0)
	char                  ptcl;		//协议类型
	unsigned short        plen;     //TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)
} UDP_PSDHEADER,*PUDP_PSDHEADER ;
 
#define MAX_UDP_DATA_LEN 65536
char SendBuf[MAX_UDP_DATA_LEN];
 
void init_udp_socket(){
 
       m_OutSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
       
       bool flag = true;
       setsockopt(m_OutSocket, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag));
       
       struct timeval nTimeOver={10,0};
       setsockopt(m_OutSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeOver,sizeof(struct timeval));
 
       struct ifreq ifr;
       memset(&ifr, 0, sizeof(ifr));
       strncpy(ifr.ifr_name, NETWORK_CAP, strlen(NETWORK_CAP));
       setsockopt(m_OutSocket, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr));
    
       m_SocketOut.sin_family = AF_INET;
       m_SocketOut.sin_addr.s_addr = inet_addr(DEST_IP);
       m_SocketOut.sin_port = (u_short)DEST_PORT;
      
}
 
unsigned short CalculateChecksum(char *buffer1, int len1, char *buffer2, int len2)
{
	unsigned long checksum=0;
	unsigned short* buffer;
	int i=0;
	buffer = (unsigned short*) buffer1;
	for (i = 0; i < (int)(len1/sizeof(unsigned short)); i++)
		checksum += buffer[i];
	
	buffer = (unsigned short*) buffer2;
	for (i = 0; i < (int)(len2/sizeof(unsigned short)); i++)
		checksum += buffer[i];
	
	if ((len2 & 0x1) != 0) 
        checksum += (unsigned char) buffer2[len2-1];
	
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >>16); 
	return (unsigned short)(~checksum); 
}
 
void FinalIPHeader(char *pIpAndDataBuffer, int length)
{
	IPHEADER* pIpHeader = (IPHEADER*) pIpAndDataBuffer;
	char* pDataBuffer = pIpAndDataBuffer + sizeof(IPHEADER);
	int dataLen = length - sizeof(IPHEADER);
	pIpHeader->checksum = CalculateChecksum(pIpAndDataBuffer, sizeof(IPHEADER), pDataBuffer, dataLen);
	pIpHeader->checksum = CalculateChecksum(pIpAndDataBuffer, sizeof(IPHEADER), pDataBuffer, 0);
}
 
 
void FinalUdpHeader(char *pUdpAndDataBuffer, int length)
{
	UDP_PSDHEADER UDP_PSD_HEADER;
	memset(&UDP_PSD_HEADER,0,sizeof(UDP_PSDHEADER));
	UDP_HEADER* pUdpHeader = (UDP_HEADER*) pUdpAndDataBuffer;
	char* pDataBuffer = pUdpAndDataBuffer + sizeof(UDP_HEADER);
	int dataLen = length - sizeof(UDP_HEADER);
	
	UDP_PSD_HEADER.saddr = inet_addr(SRC_IP);
	UDP_PSD_HEADER.daddr = inet_addr(DEST_IP);
	UDP_PSD_HEADER.mbz   = 0; 
	UDP_PSD_HEADER.ptcl  = IPPROTO_UDP; 
	UDP_PSD_HEADER.plen  = htons(length); 
	
	pUdpHeader->nCheckSum = CalculateChecksum((char*) &UDP_PSD_HEADER, sizeof(UDP_PSD_HEADER), pUdpAndDataBuffer, length);
 
}
 
void ConstructUdpHeader(UDP_HEADER *pUdpHeader, int dataLength)
{
    pUdpHeader->nSourPort	= htons((unsigned short)(SRC_PORT));
    pUdpHeader->nDestPort	= htons((unsigned short)(DEST_PORT));
    pUdpHeader->nLength	= htons(sizeof(UDP_HEADER) + dataLength);
    pUdpHeader->nCheckSum	= 0;
}
 
void ConstructIPHeader(IPHEADER *pIpHeader, int dataLength)
{
 
	pIpHeader->h_lenver			= 0x45; 	//ip v4
	pIpHeader->tos				= 0;
	pIpHeader->total_len			= htons(dataLength);
	pIpHeader->ident            		= htons(rand());
	pIpHeader->frag_and_flags		= 0;
	pIpHeader->ttl				= 128;
	pIpHeader->proto			= IPPROTO_UDP;
	pIpHeader->checksum			= 0;
	pIpHeader->sourceIP        		= inet_addr(SRC_IP);
	pIpHeader->destIP			= inet_addr(DEST_IP);
}
 
void send_my(const char* buff,int length){
 
    if( buff == NULL){
        return;
    }
 
   IPHEADER ipHeader;
   memset(&ipHeader,0,sizeof(IPHEADER));
   ConstructIPHeader(&ipHeader,length+sizeof(IPHEADER)+sizeof(UDP_HEADER));
 
   UDP_HEADER udpHeader;
   memset(&udpHeader,0,sizeof(UDP_HEADER));
   ConstructUdpHeader(&udpHeader,length);
   
   memset(SendBuf, 0, MAX_UDP_DATA_LEN);
   memcpy(SendBuf, &ipHeader, sizeof(IPHEADER));
   memcpy(SendBuf+sizeof(IPHEADER), &udpHeader, sizeof(UDP_HEADER));
   memcpy(SendBuf+sizeof(IPHEADER)+sizeof(UDP_HEADER), buff, length);	
  
   FinalIPHeader(SendBuf,length+sizeof(IPHEADER)+sizeof(UDP_HEADER));
   FinalUdpHeader(SendBuf+sizeof(IPHEADER),length+sizeof(UDP_HEADER));
 
   
   sendto(m_OutSocket,SendBuf,(length+sizeof(IPHEADER)+sizeof(UDP_HEADER)), 0,(struct sockaddr*) &m_SocketOut,sizeof(struct sockaddr_in));
}
 
int main(){
 
	init_udp_socket();
    int cnt = 3;
	int msgLen = 1472;
	char msg[2500] = {0};
	for(int i = 0; i < msgLen; i++)
		msg[i] = 'a';
	msg[msgLen - 1] = '\0';
	while(cnt){
		send_my(msg,strlen(msg));
		printf("send one\n");
		usleep(200);
        cnt--;
	}
 
}