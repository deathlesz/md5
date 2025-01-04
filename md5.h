#pragma once

#include <stdint.h>
#include <stdlib.h>

/*
 * calculates the hash of `message` using MD5 algorithm.
 *
 * @param message message hash of which will be calculated
 * @param size size of the message, in bytes
 * @param out pointer to an array of at least 16 bytes to store the digest
 *
 * @return 0 on success, -1 otherwise
 */
int md5_hash(const uint8_t *message, size_t size, uint8_t *out);

/*
 * converts 16-byte digest into string of length 33, which containts hexdigest
 * and null-byte at the end
 *
 * @param digest 16-byte digest
 * @param hexdigest string to store hexdigest in (should be at least 33 bytes
 * long)
 */
void to_hexdigest(const uint8_t *digest, char *hexdigest);
