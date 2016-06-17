#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <unistd.h>
#include <getopt.h>

#include "headers.h"


struct option opts[] = {
	{"config",  required_argument, NULL, 'f'},
	{"help",    no_argument,       NULL, 'h'},
	{"version", no_argument,       NULL, 'v'} 
};

int main(int argc, char ** argv)
{
	char *configfie = NULL;
	int opt = 0;
	while((opt = getopt_long(argc, argv, "f:hv", opts, NULL)) != -1)
	{
		switch (opt)
		{
			case 'f':
				configfie = strdup(optarg);
				break;

			case 'h':
				printf ("Uasge: ./lshark -hv | [-f configure file]");
				printf ("-f --config blablabla");
				printf ("-h --help blablabla");
				printf ("-v --version show version");

				return 0;

			case 'v':
				printf ("version 0.0.1");
				return 0;

			default:
				printf ("Uasge: ./lshark -hv | [-f configure file]");
				printf ("-f --config blablabla");
				printf ("-h --help blablabla");
				printf ("-v --version show version");
			return -1;
	}
	return 0;
}}