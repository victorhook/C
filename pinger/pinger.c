#include <arpa/inet.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

// Type definitions & macros
typedef unsigned char byte;
typedef unsigned short word;

typedef struct {
    byte type;
    byte code;
    word checksum;
    word ident;
    word seq_nbr;
    byte *data;
} icmp_packet;

#define ICMP_ECHO_REQUEST 8
#define ICMP_PROTO 1

#ifndef DATA_LEN
#define DATA_LEN 56
#endif

#ifndef TTL
#define TTL 64
#endif

#define ICMP_PACKET_SIZE 8 + DATA_LEN
#define IP_HEADER_SIZE 20

// Global variable
volatile word seq_nbr = 0;

void throw_error(const char msg[]) {
    printf("%s", msg);
}

word get_checksum(icmp_packet *packet) {

    word *p = (word *) packet;

    word len = ICMP_PACKET_SIZE;
    uint32_t sum = 0;

    // One's complement for each word in the packet
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }

    // In case of uneven packet-size, add last odd byte as well
    if (len == 1) {
        sum += (*p & 0x00ff);
    }

    // One's complement
	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	
    // Return inverted
	return ~sum; 
}

/* Creates an PING packet following the ICMP structure 
   The header is 8 bytes | TYPE | CODE | CHECKSUM |
                         | IDENTIFITER | SEQ_NBR  |
                         |   TIMESTAMP + DATA     |   */
icmp_packet * make_icmp_packet() {
    icmp_packet *packet = malloc(sizeof(icmp_packet));
    memset(packet, 0, sizeof(icmp_packet));
    
    packet->type = ICMP_ECHO_REQUEST;
    packet->code = 0;
    packet->checksum = 0;
    packet->ident = htons((word) getpid());
    packet->seq_nbr = htons(seq_nbr++);

    packet->data = (byte *) malloc(DATA_LEN * sizeof(byte));
    *packet->data = time(0);

    // Update the checksum after all fields has been set
    packet->checksum = get_checksum(packet);

    return packet;
}

/* Sends a single ping to the given host */
void send_ping(const char *dst) {

    struct hostent *dst_name = gethostbyname(dst);  // Retrieve destination name
    
    if (dst_name == NULL) {
        throw_error("Host doesn't exist!");
    }
    
    struct sockaddr_in dst_addr;                            // Destination address
    memset(&dst_addr, 0, sizeof(dst_addr));         
    dst_addr.sin_family = AF_INET;                          // IP4
    
    memcpy((char *) &dst_addr.sin_addr.s_addr,              // Copy the dest name to the destination struct
            dst_name->h_addr_list[0], dst_name->h_length);
    
    
    icmp_packet *packet = make_icmp_packet();                // Create an ICMP ping packet with default values
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);    // Open a socket for ICMP

    
    int bytes_send = sendto(sockfd, packet,                  // Send PING
                    (size_t) ICMP_PACKET_SIZE * sizeof(byte), 0, 
                    (struct sockaddr *) &dst_addr, (socklen_t) sizeof(dst_addr));

    if (bytes_send < 0) {
        perror("Error sending ping!");
    }

    seq_nbr++;
    
}



int main() {

    char *dst = "www.google.com";
    while (seq_nbr < 5) {
        send_ping(dst);
        sleep(1);
    }
    

    return 0;
}