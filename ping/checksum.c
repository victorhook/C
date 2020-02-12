#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void printb(uint16_t v) {
    uint16_t i, s = 1<<((sizeof(v)<<3)-1); // s = only most significant bit at 1
    for (i = s; i; i>>=1) printf("%d", v & i || 0 );
}

int calc_checksum(const uint8_t *packet, int8_t packet_len) {
    
    uint16_t sum = 0;

    for (int i = 0; i < packet_len - 1; i+=2) {
        uint16_t word;
        memcpy(&word, packet + i, 2);
        sum += ntohs(word);
        if (sum > 0xffff) {
            sum -= 0xffff;
        }    
    }

    if (packet_len & 1) {
        uint16_t word = 0;
        memcpy(&word, packet + packet_len - 1, 1);
        sum += ntohs(word);
        if (sum > 0xffff) {
            sum -= 0xffff;
        }
    }

    return htons(~sum);

}

int main() {

    uint8_t *buff = (uint8_t *) malloc(sizeof(uint8_t) * 4);
    buff[0] = 0xf0;
    buff[1] = 0xf1;
    buff[2] = 0x22;
    buff[3] = 0x33;
    
    uint8_t len = 4;
    uint16_t sum = calc_checksum(buff, len);
    printf("%X\n", sum);

    return 0;
}