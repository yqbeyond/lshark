#ifndef PKG_HEADS_H
#define PKG_HEADS_H

#endif // PKG_HEADS_H

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// package max size
#define PKG_LEN 2048

// eth header's length
#define SIZE_ETHERNET 14

// mac address length
#define ETHER_ADDR_LEN 6

// ethernet header
typedef struct ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    // destination host address
        u_char  ether_shost[ETHER_ADDR_LEN];    // source host address
        u_short ether_type;                     // IP? ARP? RARP? etc
}ETH_HEAD;

// ip header
typedef struct ip {
        u_char  ip_vhl;                 // version : ">> 4" , header length : "& 0x0f"
        u_char  ip_tos;                 // type of service
        u_short ip_len;                 // total length
        u_short ip_id;                  // identification
        u_short ip_off;                 // fragment offset field
        #define IP_RF 0x8000            // reserved fragment flag
        #define IP_DF 0x4000            // dont fragment flag
        #define IP_MF 0x2000            // more fragments flag
        #define IP_OFFMASK 0x1fff       // mask for fragmenting bits
        u_char  ip_ttl;                 // time to live
        u_char  ip_p;                   // protocol
        u_short ip_sum;                 // checksum
        struct  in_addr ip_src,ip_dst;  // source and dest address
}IP_HEAD;

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f) // ip head length
#define IP_V(ip)                (((ip)->ip_vhl) >> 4) // ip version

// ICMMP header
typedef struct icmp{
    u_char ic_type; // type
    u_char ic_code; // code
    u_short ic_sum; // checksum
}ICMP_HEAD;

// TCP header
typedef u_int tcp_seq;

typedef struct tcp {
        u_short th_sport;               // source port
        u_short th_dport;               // destination port
        tcp_seq th_seq;                 // sequence number
        tcp_seq th_ack;                 // acknowledgement number
        u_char  th_offx2;               // data offset, rsvd
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4) // compute header len
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 // window
        u_short th_sum;                 // checksum
        u_short th_urp;                 // urgent pointer
}TCP_HEAD;

// UDP header

typedef struct udp
{
    u_short uh_sport; // source port
    u_short uh_dport; // destination port
    u_short uh_len; // length
    u_short uh_sum; // check sum
}UDP_HEAD;
