#pragma once
#include <stdint.h>

/*!
 * Computes the SHA-256 message digest.
 *
 * @param M      message to be hashed
 * @param l      length of the message, M, in bits
 * @param digest buffer to store the digest, at least 32 bytes
 */
void sha256(const void *M, const uint64_t l, void *digest);
