#include <stdio.h> 
#include <sys/ioctl.h> 
#include <net/if.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

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

char* myIp(char *interface){
    struct ifreq ifr;
    char *ip = (char*)malloc(sizeof(char)*40);
    int s;

	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 
	
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip,sizeof(struct sockaddr)); 

    close(s);

    return ip;
}

char* myMac(char *interface){
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
    
    temp = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(hwaddr, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",temp[0],temp[1],temp[2],temp[3],temp[4],temp[5]);

    close(s);
    return hwaddr;
}