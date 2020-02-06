#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>

#define PORT 12000
#define ADDRESS "127.0.0.1"
#define BUFFER_SIZE 256
#define ICMP_HEADER_SIZE 8

int sockfd;

void error(const char *msg) {
    printf("%s\n", msg);
    close(sockfd);
    exit(0);
}

struct ip_header {
    uint8_t head_len;
    uint8_t ttl;
    uint32_t src;
    uint32_t dst;
};

/* Extracts the important parts of the IP Frame,
   - Header Length is needed to know where the ICMP packet starts
   - TTL -> Time To Live
   - IP src & dst                                           
*/
struct ip_header * extract_ip_header(char *buffer) {

    struct ip_header *ip_head = malloc(sizeof(struct ip_header));

    ip_head->head_len = buffer[0] & 0x0f;
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

struct icmp_packet {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t seq_nbr;
    uint16_t data_len;
    char *data;
};

uint16_t calc_checksum(char *packet, u_int16_t packet_len) {

    uint16_t word, i;
    uint32_t sum=0;
    
    for (uint16_t i = 0; i < packet_len; i += 2) {
        word = (uint16_t) ( (packet[i] << 8) & 0xff00) + (packet[i+1] & 0xff);
        sum += word;
    }

    while (sum << 16) {
        sum = (sum & 0xffff) + (sum >> 16);
        sum = ~sum;
    }

    return (uint16_t) sum;
}

/* Converts two bytes into a word and turns it from Big Endian to Little Endian */
uint16_t word(uint8_t b1, uint8_t b2) {
    uint16_t word = b1 << 8;
    return htons(word | b2);
}

/* Extracts all the headers and the data from the icmp packet */
struct icmp_packet * extract_icmp(char *buffer, uint8_t icmp_start, uint16_t packet_len) {

    struct icmp_packet *packet = malloc(sizeof(struct icmp_packet));
    packet->data_len = packet_len - icmp_start - ICMP_HEADER_SIZE;
    
    packet->data = malloc(sizeof(packet->data_len));            // BITS
    packet->type = buffer[icmp_start++];                        // 0
    packet->code = buffer[icmp_start++];                        // 1

    packet->checksum = word(buffer[icmp_start++], buffer[icmp_start++]);
    packet->identifier = word(buffer[icmp_start++], buffer[icmp_start++]);
    packet->seq_nbr = word(buffer[icmp_start++], buffer[icmp_start++]);
   
    printf("EXTRA LENGTH: %d\n", packet->data_len);

    //TODO: Extra 8 bits is the timestamp!

    uint16_t i = 0;
    while (i < packet->data_len) {
        packet->data[i] = buffer[icmp_start + i++];
    }

    i = 0;
    while (i < packet->data_len) {
        printf(" %.2X ", (uint8_t) packet->data[i++]);
    }

    printf("\n");
    

    return packet;

}

int main(void) {

    // Prepares the server address
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr(ADDRESS);

    // Creates the file descriptor for the socket
    // For the Ping utility we need to use a RAW socket type and the 
    // ICMP protocol. (We coulse use RAW proto as well)
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        error("Can't create socket!");
    }

    // Binds to the created file descriptor
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        error("Can't bind!");
    }
    
    // Prepares the address of the client and allocates
    // memory for a buffer to store the packet in.
    struct sockaddr cli_addr;
    int cli_len = sizeof(cli_addr);
    char *buffer = (char *) malloc(BUFFER_SIZE * sizeof(char));
    
    uint16_t packet_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)
                                &cli_addr, &cli_len);
    if (packet_len < 0) {
        error("Failed to recieve packet");
    }
    
    // Extracts the IP part of the packet   
    struct ip_header *ip_head = extract_ip_header(buffer);

    // Extracts the ICMP message 
    uint16_t icmp_start = ip_head->head_len * 4;
    struct icmp_packet *packet = extract_icmp(buffer, icmp_start, packet_len);

    uint16_t checksum = calc_checksum(buffer + icmp_start, packet_len - icmp_start);
    char *check = checksum ? "BAD" : "OK";
    
    printf("__________________________\n");
    printf("|    TTL      | Pkt Size |\n");
    printf("|    %d       |    %d    |\n", ip_head->ttl, packet_len);
    printf("__________________________\n");
    printf("| Type | Code | Checksum |\n");
    printf("|  %.2X  |  %.2X  |   %.4X   |\n", packet->type, packet->code, packet->checksum);
    printf("__________________________\n");
    printf("| Checksum:   |    %s    |\n", check);
    printf("__________________________\n");
    printf("| Identifier  |  Seq nbr |\n");
    printf("|    %.4X     |   %.4X   | \n", packet->identifier, packet->seq_nbr);
    printf("__________________________\n");
    printf("           DATA          \n");
    for (int i = 1; i < packet->data_len; i++) {
        if (i % 4 == 0 && i != 0) {
            //printf("\n");
        }
        //printf("  %.2X  ", (uint8_t) packet->data[i]);
        
    }
    printf("\n");

    
    close(sockfd);
    
    return 0;
}



