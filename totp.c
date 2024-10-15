#include "totp.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

uint32_t totp_generate(uint8_t *secret, size_t secret_len, uint64_t time_step){
    uint64_t unixTime = time(NULL);
    uint64_t time_step_count = unixTime / time_step;

    uint8_t time_bytes[8];
    for (int i = 7; i >= 0; i--){
        time_bytes[i] = time_step_count & 0xff;                 // get the least significant byte, add to array and shift time_step_count by a byte
        time_step_count >>= 8;                                  // turn time step into 8 byte array to be able to use in sha1 hmac
    }

    uint8_t hmac_result[SHA1_LENGTH];
    HMAC(EVP_sha1(), secret, secret_len, time_bytes, sizeof(time_bytes), hmac_result, NULL);

    uint32_t truncatedHmac = totp_truncate(hmac_result);
    return truncatedHmac % 1000000;                             // further truncate output to get 6 digit integer
}

static uint32_t totp_truncate(uint8_t *hmac_result){
    uint8_t offset = hmac_result[SHA1_LENGTH - 1] & 0xf;        // get the last 4 bits of the last byte
    uint32_t truncated = 
        ((hmac_result[offset] & 0x7f) << 24) |                  //0x7f makes sure num is positive by ANDing the most significant bit
        (hmac_result[offset + 1] << 16)      |
        (hmac_result[offset + 2] << 8)       |                  //rfc 6238's example implementation specifies ANDing with 0xff but this isn't necessary here
        (hmac_result[offset + 3]);                              //as we are using the stdint unsigned 8 bit int type, and Java bytes are signed (why?)
    return truncated;
}

uint8_t totp_validate(uint8_t *secret, size_t secret_len, uint32_t totp, uint64_t time_step){               // useful utility!
    uint32_t expectedTOTP = totp_generate(secret, secret_len, time_step);
    return expectedTOTP == totp;
}
