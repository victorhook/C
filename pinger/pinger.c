#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


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

typedef struct {
    uint8_t head_len;
    uint8_t ttl;
    uint32_t src;
    uint32_t dst;
} ip_header;

#define ICMP_ECHO_REQUEST 8
#define ICMP_PROTO 1

#ifndef DATA_LEN
#define DATA_LEN 56
#endif

#ifndef TTL
#define TTL 64
#endif

#define ICMP_HEADER_SIZE 8
#define ICMP_PACKET_SIZE ICMP_HEADER_SIZE + DATA_LEN
#define IP_HEADER_SIZE 20

#define TIMEOUT 1000000
#define BUFF_SIZE 1024 * sizeof(byte)

int rec_ping(int sockfd, clock_t time_sent);


/* Extracts the important parts of the IP Frame,
   - Header Length is needed to know where the ICMP packet starts
   - TTL -> Time To Live
   - IP src & dst                                            */
ip_header * extract_ip_header(char *buffer) {

    ip_header *ip_head = malloc(sizeof(ip_header));

    ip_head->head_len = 4 * (buffer[0] & 0x0f);
    ip_head->ttl = buffer[8];

    ip_head->src = buffer[12] << 24;
    ip_head->src |= buffer[13] << 16;
    ip_head->src |= buffer[14] << 8;
    ip_head->src |= buffer[15] << 0;

    ip_head->dst = buffer[16] << 24;
    ip_head->dst |= buffer[17] << 16;
    ip_head->dst |= buffer[18] << 8;
    ip_head->dst |= buffer[19] << 0;

    return ip_head;
}

/* Prints a 32 bit ip address in a readble x.x.x.x format */
void print_ip(uint32_t ip) {
    uint8_t one = ip >> 24;
    uint8_t two = ip >> 16;
    two &= 0x000000ff;
    uint8_t three = ip >> 8;
    three &= 0x000000ff;
    uint8_t four = ip & 0x000000ff;

    printf("%d.%d.%d.%d", one, two, three, four);
}



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
    
    rec_ping(sockfd, clock());

}



void delay(int ms) { 
    printf("%d", getpid());
    clock_t start = clock();
    while (clock() - start < ms);

} 

icmp_packet * extract_icmp(byte *buf, int start, int len) {
    
    icmp_packet *icmp_reply = malloc(sizeof(icmp_packet));
    memset(icmp_reply, 0, sizeof(icmp_packet));

    icmp_reply->type = buf[start++];
    icmp_reply->code = buf[start++];
    icmp_reply->checksum = (buf[start++] << 8) | buf[start++];
    icmp_reply->ident = (buf[start++] << 8) | buf[start++];
    icmp_reply->seq_nbr = (buf[start++] << 8) | buf[start++];
    icmp_reply->data = malloc(len - start - ICMP_HEADER_SIZE * sizeof(byte));

    while (start < len) {
        *icmp_reply->data++ = buf[start++];
    }

    printf("%.4X\n", icmp_reply->checksum);
    icmp_reply->checksum = 0;
    word chksum = get_checksum(icmp_reply);
    printf("%.4X\n", chksum);


    return icmp_reply;

}

int rec_ping(int sockfd, time_t start) {

    struct timeval timeout;
    fd_set readfs;

    timeout.tv_sec = 1;

    FD_ZERO(&readfs);
    FD_SET(sockfd, &readfs);

    if (!select(sockfd + 1, &readfs, NULL, NULL, &timeout)) {
        throw_error("Failed to receive ping!\n");
    }

    struct sockaddr_in reply_addr;
    memset(&reply_addr, 0, sizeof(struct sockaddr_in));
    int len = sizeof(struct sockaddr_in);

    byte *buf = (byte *) malloc(BUFF_SIZE);
    
    
    int packet_len = recvfrom(sockfd, buf, BUFF_SIZE, 0, (struct sockaddr *) &reply_addr, &len);

    ip_header *ip_head = extract_ip_header(buf);
    icmp_packet *icmp_reply = extract_icmp(buf, ip_head->head_len, packet_len);

    //packet_len - ip_head->head_len

    
    printf("__________________________\n");
    printf("|    TTL      | Pkt Size |\n");
    printf("|    %d       |    %d    |\n", ip_head->ttl, packet_len);
    printf("__________________________\n");
    printf("| Type | Code | Checksum |\n");
    printf("|  %.2X  |  %.2X  |   %.4X   |\n", icmp_reply->type, icmp_reply->code, icmp_reply->checksum);
    printf("__________________________\n");
    //printf("| Checksum:   |    %s    |\n", icmp_reply->checksum);
    printf("__________________________\n");
    printf("| Identifier  |  Seq nbr |\n");
    printf("|    %.4X     |   %.4X   | \n", icmp_reply->ident, icmp_reply->seq_nbr);
    printf("__________________________\n");
    printf("           DATA          \n");

}


int main() {
    
    send_ping("www.google.com");

    

    return 0;
}