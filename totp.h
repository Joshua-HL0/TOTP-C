#ifndef TOTP_H
#define TOTP_H

#include <stdint.h>
#include <string.h>

#define SHA1_LENGTH 20

uint32_t totp_generate(uint8_t *secret, size_t secret_len, uint64_t time_step);

static uint32_t totp_truncate(uint8_t *hmac_result);

uint8_t totp_validate(uint8_t *secret, size_t secret_len, uint32_t totp, uint64_t time_step);

#endif
