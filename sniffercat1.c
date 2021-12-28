#include<errno.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<netpacket/packet.h>
#include<net/if.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<unistd.h>
#include<errno.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<netpacket/packet.h>
#include<net/if.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<unistd.h>



//these are the function prototypes
void ProcessPacket(unsigned char* , int);
void print_ethernet_header(unsigned char* , int);
int iface_get_id(int, char*);
int iface_bind(int, int);

// functions



int iface_get_id(int fd, char *device)
{
    struct ifreq	ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) != 0)
    {
        perror("SIOCGIFINDEX");
        return -1;
    }

    return ifr.ifr_ifindex;
}

// from libpcap - binds an existing AF_PACKET socket to an interface index

int iface_bind(int fd, int ifindex)
{
    struct sockaddr_ll  	sll;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family      	= AF_PACKET;
    sll.sll_ifindex     	= ifindex;
    sll.sll_protocol    	= htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
        if (errno == ENETDOWN) {
            perror("bind interface down");
            return ENETDOWN;
        } else {
            perror("bind");
            return -1;
        }
    }

    return 0;
}

// main entry point

int main(int argc, char *argv[])
{

    if(argc != 2)
    {
        printf("usage: %s [interface]\n", argv[0]);
        return 1;
    }

    char *interfacename = argv[1];

    if(argc < 2){
        perror("socket");
    }

    int saddr_size, data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));



    // calls to interface binding funcs from libpcap

    int ifindex = 0;
    ifindex = iface_get_id(sock_raw, interfacename);
    if(ifindex < 0)
    {
        // perror("ifindex");
        return 1;
    }

    if( iface_bind(sock_raw, ifindex) != 0 )
    {
        perror("iface_bind");
        return 1;
    }

    printf("Starting sniffer on interface %s\n", argv[1]);

    while(1)
    {
        saddr_size = sizeof saddr;
        // receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            perror("recvfrom");
            return 1;
        }
        // now process the packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished.\n");
    return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
    print_ethernet_header(buffer , size);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    // printf("Ethernet Header\n");
    printf(" src %.2X:%.2X:%.2X-%.2X:%.2X:%.2X --", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf(" dst %.2X:%.2X:%.2X-%.2X:%.2X:%.2X --", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf(" proto 0x%.4X \n",htons((__be16)eth->h_proto));
}
