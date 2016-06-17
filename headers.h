// 802.11 mac header rfc 894
typedef struct _eth_hdr
{
	unsigned char destmac[6]; // destination mac address
	unsigned char srcmac[6]; // source mac adress
	unsigned short eth_type; // ethernet type ( IP: 0x0800)
}eth_hdr;

// mac tail
typedef struct _eth_tail
{
	unsigned int fcs; // frame check sequence
}ethtail;

/* ip header from rfc 791
 *
 * format:
 *
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver= 4 |IHL= 5 |Type of Service|        Total Length = 21      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Identification = 111     |Flg=0|   Fragment Offset = 0   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Time = 123  |  Protocol = 1 |        header checksum        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         source address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      destination address                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

typedef struct _ip_hdr
{
	unsigned char ver; // 4 bit, version
	unsigned char ihl; // 4 bit, header length
	unsigned char tos; // 8 bit, type of service
	unsigned short total_len; // 16 bit, total length
	unsigned short id; // 16 bit, identifier
	unsigned short flg; // 3 bit, flag
	unsigned short frag_offset; // 13 bit, fragment offset
	unsigned char ttl; // 8 bit,time to live
	unsigned char proto; // 8 bit, protocol
	unsigned short chk_sum; // 16 bit, header checksum
	unsigned int src_addr; // 32 bit, source address
	unsigned int dst_addr; // 32 bit, destination addrress
}iphdr;



/* tcp header from rfc 793
 *
 * format:
 *
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
typedef struct _tcp_hdr
{
	unsigned short src_port; // 16 bit, source port
	unsigned short dst_port; // 16 bit, destination port
	unsigned int seq_no; // 32 bit, seq number
	unsigned int ack; // 32 bit, acknowledgment number
	unsigned char data_off; // 4 bit, data offset
	unsigned char res; // 6 bit, reserve to use
	unsigned char flg; // 6 bit, (URG, ACK, PSH, RST, SYN, FIN)
	unsigned short Win; // 16 bit, window
	unsigned short chk_sum; // 16 bit cheack sum
	unsigned urg_pntr; // 16 bit, urgent pointer
}tcphdr;


/* udp header from rfc 768
 *
 * format :
 *
 *  0      7 8     15 16    23 24    31  
 * +--------+--------+--------+--------+ 
 * |     Source      |   Destination   | 
 * |      Port       |      Port       | 
 * +--------+--------+--------+--------+ 
 * |                 |                 | 
 * |     Length      |    Checksum     | 
 * +--------+--------+--------+--------+ 
 * |                                     
 * |          data octets ...            
 *  +---------------- ...                
 */

typedef struct _udp_hdr
{
 	unsigned short src_port; // source port
 	unsigned short dst_port; // destination port
 	unsigned short uhl; // length
 	unsigned short chk_sum; // check sum

}udphdr;

/* icmp header from rfc 792
 *
 * format:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             unused                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Internet Header + 64 bits of Original Data Datagram      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct _icmp_hdr
{
	unsigned char type; // type
	unsigned char code; // code
	unsigned short chk_sum; // check sum
}icmphdr;
