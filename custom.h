#include <stdio.h> 
#include <sys/ioctl.h> 
#include <net/if.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ip.h"
#include "mac.h"

typedef struct {
	char* dev_;
} Param;

void usage() {  
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 4 || argc % 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

//굳이 문자열로 바꿔서 다시 보내줄 이유가 없다? IP 구조체를 사용하여 바로 보내자
Ip myIp(char *interface){
	struct sockaddr_in *addr;
	struct ifreq ifr;
    int s;
	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 
	
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}
    close(s);
	addr = (struct sockaddr_in *)&(ifr.ifr_addr);
	return htonl(addr->sin_addr.s_addr);
}

//굳이 문자열로 바꿔서 다시 보내줄 이유가 없다? MAC 구조체를 사용하여 바로 보내자
Mac myMac(char *interface){
    struct ifreq ifr;
	int s; 
    unsigned char *temp;
	char *hwaddr = (char *)malloc(sizeof(char)*6);
	
	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 

	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}
    
    close(s);
    return Mac((unsigned char*)ifr.ifr_hwaddr.sa_data);
}