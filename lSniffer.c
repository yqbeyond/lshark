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
	int sock, pkg_len;
	char buffer[2048];
	unsigned char *iphead, *ethhead, *arphead, *tcphead, *udphead, *icmphead, *httphead, *igmphead; // ftphead is optional
	struct ifreq ethreq;
	int total_pkgs = 0;

	// set raw socket to accpet allow the packages.
	if ( (sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
	{
		perror("\nRaw socket create failed.\n");
		exit(1);
	}
	// set NIC work on promiscuous mode
	strncpy(ethreq.ifr_name,"enp3s0", IFNAMSIZ); // you can change 'wlp2s0' to 'eth0' when neccessary.
	if (ioctl(sock, SIOCGIFFLAGS, &ethreq)==-1)
	{
		perror("Promiscuous mode set failed.\n");
		close(sock);
		exit(1);
	}

	// capture the packages
	while (1)
	{
		pkg_len = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
		++total_pkgs;
		printf("<<< The %d packet with %d bytes >>>\n", total_pkgs, pkg_len);
		// to check if the package is a full header. eth(14) + ip(20) + tcp/udp(8)
		if (pkg_len < 42) // invalid pkg
		{
			perror("recvfrom():");
			exit(0);
		}

		ethhead = buffer;
		printf("Dest MAC Address: %02x-%02x-%02x-%02x-%02x-%02x\n", ethhead[0], ethhead[1], ethhead[2], ethhead[3], ethhead[4], ethhead[5]);
		printf("Source MAC Address: %02x-%02x-%02x-%02x-%02x-%02x\n", ethhead[6], ethhead[7], ethhead[8], ethhead[9], ethhead[10], ethhead[11]);

		if (ethhead[12] == 0x08 && ethhead[13] == 0x06) // arp
		{
			// arp process code
			arphead = buffer + 14;
			printf("Source MAC Address: %02x-%02x-%02x-%02x-%02x-%02x\n", arphead[8], arphead[9], arphead[10], arphead[11], arphead[12], arphead[13]);
			printf("Source host ip address %d.%d.%d.%d\n", arphead[14],arphead[14], arphead[15],arphead[16]);
			printf("Dest MAC Address: %02x-%02x-%02x-%02x-%02x-%02x\n", arphead[17], arphead[18], arphead[19], arphead[20], arphead[21], arphead[22]);
			printf("Dest host ip address %d.%d.%d.%d\n", arphead[22],arphead[23], arphead[24],arphead[25]);
		}
		else if (ethhead[12] == 0x08 && ethhead[13] == 0x00); // ip
		{
			iphead = buffer + 14; // skip eth head
			if (*iphead == 0x45) // ipv4 and ip head length(20 = 4 * 5)
			{
				// print dest or src mac adddress
				printf("Source host ip address %d.%d.%d.%d\n", iphead[12],iphead[13], iphead[14],iphead[15]);
				printf("Dest host ip address %d.%d.%d.%d\n", iphead[16],iphead[17], iphead[18],iphead[19]);

				if(iphead[9] == 6) // tcp 
				{
					tcphead = iphead + 20;
					printf("TCP Package\n");
					printf("Source port:%d, Dest port %d\n", (tcphead[0]<<8)+tcphead[1], (tcphead[2]<<8)+tcphead[3]);

					if ((tcphead[0]<<8) + tcphead[1] == 80 || (tcphead[2]<<8)+tcphead[3] == 80)
					{
						printf("Htpp Pacakge\n");
						// http process code
					}
					else if ((tcphead[0]<<8) + tcphead[1] == 21 || (tcphead[2]<<8)+tcphead[3] == 21)
					{
						printf("Ftp Control Package\n");
						// ftp control message package process code
					}
					else if ((tcphead[0]<<8) + tcphead[1] == 20 || (tcphead[2]<<8)+tcphead[3] == 20)
					{
						printf("Ftp Data Package\n");
						// ftp data package process code
					}
					else if ((tcphead[0]<<8) + tcphead[1] == 22 || (tcphead[2]<<8)+tcphead[3] == 22)
					{
						printf("SSH Package\n");
						// ssh package process code
					}
				}
				else if(iphead[9] == 17) // udp
				{
					udphead = iphead + 20;
					printf("UDP Package\n");
					printf("Source port:%d, Dest port %d\n", (udphead[0]<<8)+udphead[1], (udphead[2]<<8)+udphead[3]);
					// udp package process code
				}
				else if (iphead[9] == 1) // icmp
				{
					icmphead = iphead + 20;
					printf("ICMP Package\n");
					printf("Type: %d, Code: %d\n", icmphead[0], icmphead[1]);
					if (icmphead[0] == 8 && icmphead[1] == 0)
					{
						printf("Icmp echo request\n");
					}
					else if (icmphead[0] == 0 && icmphead[1] == 0)
					{
						printf("Icmp echo response\n");
					}
					else
					{
						printf("Other type icmp type\n");
					}
					// other icmp process code.
				}
				else if (iphead[9] == 2) // igmp
				{
					igmphead = iphead + 20;
					printf ("IGMP Package\n");
					printf ("Version: %d, Type\n", igmphead[0]>>4, igmphead[0]);
					printf ("Group IP: %d.%d.%d.%d\n", igmphead[4], igmphead[5], igmphead[6], igmphead[7]);
					// other igmp process code.
				}
				else // other protocols
					printf("Protocol id:%d\n",iphead[9]);
			}
		}
		printf ("\n");
	}
	return 0;
}
