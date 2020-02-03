#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>

#define PORT 12000
#define ADDRESS "127.0.0.1"
#define BUFFER_SIZE 256

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
    printf("\nListening\n");    // Debugging
    
    // Prepares the address of the client and allocates
    // memory for a buffer to store the packet in.
    struct sockaddr cli_addr;
    int cli_len = sizeof(cli_addr);
    char *buffer = (char *) malloc(BUFFER_SIZE * sizeof(char));
    
    int packet_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)
                                &cli_addr, &cli_len);
    if (packet_len < 0) {
        error("Failed to recieve packet");
    }
    
    // Extracts the     
    struct ip_header *ip_head = extract_ip_header(buffer);
    
    printf("%d\n", ip_head->dst);
    
    printf("Packet size: %d  ttl: %d\n", packet_len, ip_head->ttl);

    close(sockfd);
    
    return 0;
}


