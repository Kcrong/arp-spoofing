/*
 * Arp Spoofing 을 하려면, 패킷의 내부 헤더나 데이터를 마음대로 조작할 수 있는 raw socket 을 사용해야 한다.
 */



/*
 * Raw socket 에 의해 Packet 이 만들어 지는 과정 ( http://research.hackerschool.org/study/SS_1.htm )
 * 1. socket 함수를 이용해 소켓을 생성. 이때 인자는 무조건 SOCK_RAW 로 지정, 세번째 인자(protocol) 은 IPPROTO_RAW 로 지정
 * 2. setsockopt 함수를 이용해 직접 헤더를 건드릴 수 있도록 소켓의 옵션을 변경한다.
 * 3. IP Header 내용을 직접 채운다.
 * 4. TCP Header 내용을 채운다.
 * 5. 패킷을 보낸다.
 */


#include <stdio.h>
#include <stdlib.h>  // For exit()
#include <sys/socket.h>  // For socket()
#include <unistd.h>  // For getuid()
#include <string.h> // For memset()
#include <arpa/inet.h> // For inet_addr
#include <netinet/tcp.h>

#include <netinet/ip.h>

void check_root(){
    if(getuid() && geteuid()){
        printf("Need Root Permission!");
        exit(-1);
    }
}

void printerror(char *string){
    printf("%s", string);
    exit(-1);
}

int main() {
    check_root();

    int sockfd;

    // make RAW socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // socket() fail check
    if(sockfd < 0)  printerror("socket() error");

    /* int setsockopt(
     *      int s,                  socket file descriptor
     *      int  level,             protocol level
     *      int  optname,           option name
     *      const  void  *optval,   option value
     *      socklen_t optlen        option length
     *      );
    */
    //
    const int one = 1;

    // setsockopt 의 4번째 인자에는 1을 가르키고 있는 주소를 주어야 하므로,
    // 1을 가지고 있는 변수 one 을 만든 후, 그 변수의 주소값을 넘겨줌
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one));

    // OSI 7 Layer에 따르면 Packing 순서는 IP (3계층) -> TCP (4계층) 이므로 IP 헤더가 TCP 헤더보다 먼저 와야함.

    unsigned char packet[40]; // iphdr 20 + tcphdr 20 = 40

    // packet 초기화
    memset(packet, 0, sizeof(packet));

    // Input tcp header structure
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 20);


/*
  TCP Header Format


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
    // Let's Fill header!




    // Set Source Port to My Birth Day
    tcp_header->source = htons(1010);  // htons: short integer -> network byte order

    // Set Dest Port to ARP port 219
    tcp_header->dest = htons(219);

    // Setting Sequence Number
    tcp_header->seq = htonl(12341234); // htonl: long integer -> network byte order

    // Setting Ack Number
    tcp_header->ack_seq = htonl(43214321);

    // Setting offset
    tcp_header->doff = 5;

    // Setting SYN flag
    tcp_header->syn = 1;

    // Setting Window Size
    tcp_header->window = htons(512);

    // Message check var
    tcp_header->check = 1;

    /*
  TCP Header Format


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             1010              |              219              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          12341234                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          43214321                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       |           | | | | | | |                               |
   |   5   |     0     |0|0|0|0|1|0|              512              |
   |       |           | | | | | | |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              1                |              1                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    0                          |     0         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              0                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

    // Input ip header structure
    struct iphdr *ip_header = (struct iphdr *)packet;

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


    // ipv4
    ip_header->version = 4;

    // ip header length
    ip_header->ihl = 5;

    // Setting Protocol (TCP)
    ip_header->protocol = IPPROTO_TCP;

    // Setting Packet length
    ip_header->tot_len = 40;

    // Setting packet id
    ip_header->id = htons(101);

    // Setting TTL
    ip_header->ttl = 60;

    // Setting Checksum data
    ip_header->check = 1;

    // Setting Sender IP
    ip_header->saddr = inet_addr("123.123.123.123");

    // Setting Receiver IP
    ip_header->daddr = inet_addr("192.168.1.35");


/*  Now Status
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   4   |   5   |   IPPROTO_TCP |              40               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              101              |0 0 0|            0            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      60       |       0       |               1               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     123.123.123.123                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     192.168.1.35                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      0                        |      0        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(12345);
    address.sin_addr.s_addr = inet_addr("192.168.1.35");

    // Send packet
    sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&address, sizeof(address));

}