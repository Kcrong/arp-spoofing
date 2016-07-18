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

#include <netinet/ip.h>

struct iphdr *ip = (struct iphdr *) buffer;

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

    if(sockfd < 0)  printerror("socket() error");

    /* int setsockopt(
     *      int s,
     *      int  level,
     *      int  optname,
     *      const  void  *optval,
     *      socklen_t optlen
     *      );
    */








}