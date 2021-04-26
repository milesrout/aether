#include <sys/random.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "util.h"
#include "monocypher.h"

void
dumpbytes(const uint8_t *data, size_t size)
{
	while (size--)
		fprintf(stderr, "%02x", *data++);
}

void
displaykey(const char *name, const uint8_t *key, size_t size)
{
	fprintf(stderr, "%s:\n", name);
	dumpbytes(key, size);
	fprintf(stderr, "\n");
}

void
randbytes(uint8_t *data, size_t size)
{
	ssize_t result, ssize = size;

	do result = getrandom(data, size, 0);
	while (ssize != result);
}

void
generate_hidden_keypair(uint8_t hidden_key[32], uint8_t private_key[32])
{
	uint8_t seed[32];
	randbytes(seed, 32);
	crypto_hidden_key_pair(hidden_key, private_key, seed);
	crypto_wipe(seed, 32);
}

void
generate_kex_keypair(uint8_t public_key[32], uint8_t private_key[32])
{
	randbytes(private_key, 32);
	crypto_key_exchange_public_key(public_key, private_key);
}

void
generate_sig_keypair(uint8_t public_key[32], uint8_t private_key[32])
{
	randbytes(private_key, 32);
	crypto_sign_public_key(public_key, private_key);
}

/* BEGIN: these are derived from monocypher directly */
void
store32_le(uint8_t out[4], uint32_t in)
{
    out[0] = (uint8_t)( in        & 0xff);
    out[1] = (uint8_t)((in >>  8) & 0xff);
    out[2] = (uint8_t)((in >> 16) & 0xff);
    out[3] = (uint8_t)((in >> 24) & 0xff);
}

uint32_t
load32_le(const uint8_t s[4])
{
    return (uint32_t)s[0]
        | ((uint32_t)s[1] <<  8)
        | ((uint32_t)s[2] << 16)
        | ((uint32_t)s[3] << 24);
}

uint64_t
load64_le(const uint8_t s[8])
{
    return load32_le(s) | ((uint64_t)load32_le(s+4) << 32);
}

void
store64_le(uint8_t out[8], uint64_t in)
{
    store32_le(out    , (uint32_t)in );
    store32_le(out + 4, in >> 32);
}
/* END: these are derived from monocypher directly */

int
check_key(const uint8_t isk[32], const char name[4], const uint8_t key[32], const uint8_t sig[64])
{
	uint8_t msg[36] = { 0 };
	int result;

	memcpy(msg, name, 4);
	memcpy(msg + 4, key, 32);
	result = crypto_check(sig, isk, msg, 36);
	crypto_wipe(msg, 36);

	return result;
}

void
sign_key(uint8_t sig[64],
	const uint8_t isk_prv[32], const uint8_t isk[32],
	const char name[4], const uint8_t key[32])
{
	uint8_t msg[36] = { 0 };

	memcpy(msg, name, 4);
	memcpy(msg + 4, key, 32);
	crypto_sign(sig, isk_prv, isk, msg, 36);
	crypto_wipe(msg, 36);
}
