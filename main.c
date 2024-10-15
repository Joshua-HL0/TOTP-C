#include "totp.h"
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

static int base32_decode(char *encoded, uint8_t *result, int bufSize) {        // standard base32 decoding function, i didn't come up with this
    int buffer = 0;
    int bitsLeft = 0;
    int count = 0;

    for (char *ptr = encoded; count < bufSize && *ptr; ptr++){
        char ch = toupper(*ptr);
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-'){
            continue;
        }
        buffer <<= 5;

        if (ch == '='){
            continue;
        }
        else if (ch >= 'A' && ch <= 'Z') {
            buffer |= (ch - 'A');
        }
        else if (ch >= '2' && ch <= '7'){
            buffer |= (ch - '2' + 26);
        }
        else{
            return -1;
        }

        bitsLeft += 5;
        if (bitsLeft >= 8){
            result[count++] = buffer >> (bitsLeft - 8);
            bitsLeft -= 8;
        }
    }

    return count;
}

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Usage: %s <Base32 encoded secret\n", argv[0]);
        return 1;
    }

    uint8_t secret[32];
    int secret_len = base32_decode(argv[1], secret, sizeof(secret));
    if (secret_len < 0){
        fprintf(stderr, "Invalid Base32 encoded secret\n");
        return 1;
    }

    uint64_t time_step = 30; //standard time step
    
    uint32_t totp = totp_generate(secret, secret_len, time_step);
    printf("%06u\n", totp); // %06 to make sure all 6 digits are printed, just in case the totp number is below 100,000

    return 0;
}
