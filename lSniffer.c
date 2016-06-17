/*
 * Code from my teacher, I'll perfect it later.
 *
 * You can capture all the TCP/UDP pacakges that pass your NIC, but Just capture, Nothing more.
 * Alittle stupid. Just for fun. Do not be evil.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <stdlib.h>


int main(int argc, char **argv)
{
    int sock, n;
    char buffer[2048];
    unsigned char *iphead, *ethhead;
    struct ifreq ethreq;
    int no=0;

    // set raw socket to accpet allow the packages.
    if ( (sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0)
    {
        perror("\nRaw socket create failed.\n");
        exit(1);
    }
    // set NIC work on promiscuous mode
    strncpy(ethreq.ifr_name,"wlp2s0",IFNAMSIZ); // you can change 'wlp2s0' to 'eth0' when neccessary.
    if (ioctl(sock,SIOCGIFFLAGS,&ethreq)==-1)
    {
        perror("\nPromiscuous mode set failed.\n");
        close(sock);
        exit(1);
    }

    // capture the packages
    while (1)
    {
        n = recvfrom(sock,buffer,2048,0,NULL,NULL);
        no++;
        printf("\n************%d packet %d bytes ************\n",no,n);
        // to check if the package is a full header. eth(14) + ip(20) + tcp/udp(8)
        if (n<42)
        {
            perror("recvfrom():");
            exit(0);
        }

        ethhead = buffer;
        printf("Dest MAC address: "
               "%02x:%02x:%02x:%02x:%02x:%02x\n",
               ethhead[0],ethhead[1],ethhead[2],
               ethhead[3],ethhead[4],ethhead[5]);
        printf("Source MAC address: "
               "%02x:%02x:%02x:%02x:%02x:%02x\n",
               ethhead[6],ethhead[7],ethhead[8],
               ethhead[9],ethhead[10],ethhead[11]);

        iphead = buffer+14; /* Skip ethernet header */
        if (*iphead==0x45)
        {
            /* Double check for IPv4 and no options present */
            printf("Source host %d.%d.%d.%d\n",
                   iphead[12],iphead[13],
                   iphead[14],iphead[15]);
            printf("Dest host %d.%d.%d.%d\n",
                   iphead[16],iphead[17],
                   iphead[18],iphead[19]);
            printf("Source port:%d,Dest port %d\n",
                   (iphead[20]<<8)+iphead[21],
                   (iphead[22]<<8)+iphead[23]);
            if(iphead[9]==6)
                printf("TCP\n");
            else if(iphead[9]==17)
                printf("UDP\n");
            else
                printf("protocol id:%d\n",iphead[9]);
        }
    }

}
