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
#include <stdint.h>


#define DST_IP "192.168.0.102"
#define DST_PORT 6666
#define SRC_IP "192.168.0.101"
#define SRC_PORT 6666
#define TEST_MESSAGE "This test udp message!"
#define NETWORK_CAP "myveth0"

unsigned int udpSocket;

struct sockaddr_in dstAddr;

typedef struct _IpHdr {
    uint8_t  versionIhl;		/**< 8bit 4bit版本 + 4bit首部长度 */
	uint8_t  typeOfService;	    /**< 8bit 服务类型 */
	uint16_t totalLength;	    /**< 16bit 总长度(字节数) */
	uint16_t packetId;		    /**< 16bit 标识 */
	uint16_t fragmentOffset;	/**< 16bit 3bit标志 + 13bit片偏移 */
	uint8_t  timeToLive;		/**< 8bit 生存时间(TTL) */
	uint8_t  nextProtoId;		/**< 8bit 上层协议 */
	uint16_t hdrChecksum;	    /**< 16bit 检验和 */
	uint32_t srcAddr;		    /**< 32bit 源IP地址 */
	uint32_t dstAddr;		    /**< 32bit 目的IP地址 */
}IpHdr;

typedef struct _UdpHdr {
    uint16_t srcPort;           /**< UDP source port. */
	uint16_t dstPort;           /**< UDP destination port. */
	uint16_t dgramLen;          /**< UDP datagram length */
	uint16_t dgramCksum;        /**< UDP datagram checksum */
}UdpHdr;

typedef struct _PseudoHdr {     /**< ip 伪包头 用于计算udp checksum */
    uint32_t srcAddr;           /**< 源ip地址 */
    uint32_t dstAddr;           /**< 目的ip地址 */
    uint8_t  zero;              /**< 置0字节 */
    uint8_t  nextProtoId;       /**< 上层协议 */
    uint16_t length;            /**< TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节) */
}PseudoHdr;

#define MAX_UDP_DATA_LEN 65536
char sendBuf[MAX_UDP_DATA_LEN];

void initUdpSocket () {
    udpSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    bool flag = true;
    setsockopt(udpSocket, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag));
    struct timeval nTimeOver={10,0};
    setsockopt(udpSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeOver,sizeof(struct timeval));
    
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_addr.s_addr = inet_addr(DST_IP);
    dstAddr.sin_port = (uint16_t)DST_PORT;
}

uint16_t calculateChecksum (){

}

void constructUdpHeader (UdpHdr *udpHdr, uint16_t dataLength) {
    udpHdr->srcPort     = htons((uint16_t)SRC_PORT);
    udpHdr->dstPort     = htons((uint16_t)DST_PORT);
    udpHdr->dgramLen    = htons(sizeof(UdpHdr) + dataLength);
    udpHdr->dgramCksum  = 0;
}

void constructIpHeader (IpHdr *iphdr, uint16_t dataLength) {
    iphdr->versionIhl       = 0x45;      // ipv4
    iphdr->typeOfService    = 0;
    iphdr->totalLength      = htons(dataLength);
    iphdr->packetId         = htons(rand());
    iphdr->fragmentOffset   = 0;
    iphdr->timeToLive       = 128;
    iphdr->nextProtoId      = IPPROTO_UDP;
    iphdr->hdrChecksum      = 0;
    iphdr->srcAddr          = inet_addr(SRC_IP);
    iphdr->dstAddr          = inet_addr(DST_IP);
}

void sendUdpMsg (const char* buff, uint16_t length) {
    if (buff == NULL)   return;
    
    IpHdr ipHdr;
    UdpHdr udpHdr;

    memset(&ipHdr, 0, sizeof(IpHdr));
    constructIpHeader(&ipHdr, length + sizeof(IpHdr) + sizeof(UdpHdr));
    memset(&udpHdr, 0, sizeof(UdpHdr));
    constructUdpHeader(&udpHdr, length);

    memset(sendBuf, 0, MAX_UDP_DATA_LEN);
    memcpy(sendBuf, &ipHdr, sizeof(IpHdr));
    memcpy(sendBuf + sizeof(IpHdr), &udpHdr, sizeof(UdpHdr));
    memcpy(sendBuf + sizeof(IpHdr) + sizeof(UdpHdr), buff, length);

    sendto(udpSocket, sendBuf, length + sizeof(IpHdr) + sizeof(UdpHdr), 0, (struct sockaddr *) &dstAddr, sizeof(struct sockaddr_in));
}

int main(int argc, char const *argv[]) {
    /* code */
    initUdpSocket();
    uint8_t  cnt = 3;
    uint16_t msgLen = 2000;
    char     msg[2500] = {0};
    for (int i = 0; i < msgLen; i++)    msg[i] = 'a';
    msg[msgLen] = '\0';
    while (cnt) {
        sendUdpMsg(msg, strlen(msg));
        usleep(200);
        cnt--;
    }
    
    return 0;
}
