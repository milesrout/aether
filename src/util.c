/* This file is part of Æther.
 *
 * Æther is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Æther is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef __APPLE__
#include <sys/random.h>
#endif

#include "util.h"
#include "monocypher.h"

size_t
floorlog2(size_t x)
{
	return sizeof(size_t) * CHAR_BIT - 1 - __builtin_clzl((size_t)(x));
}

size_t
padme(size_t l)
{
	size_t e, s, last_bits, bit_mask;

	e = floorlog2(l);
	s = floorlog2(e) + 1;
	last_bits = e - s;
	bit_mask = last_bits == 0 ? 0 : ((uint64_t)-1L) >> (sizeof(size_t) * CHAR_BIT - last_bits);
	return (l + bit_mask) & ~bit_mask;
}


void
dumpbytes(const uint8_t *data, size_t size)
{
	while (size--)
		printf("%02x", *data++);
}

void
displaykey(const char *name, const uint8_t *key, size_t size)
{
	printf("%s:\n", name);
	dumpbytes(key, size);
	printf("\n");
}

void
displaykey_short(const char *name, const uint8_t *key, size_t size)
{
	printf("%s:\t", name);
	dumpbytes(key, size);
	printf("\n");
}

#ifdef __APPLE__
void
randbytes(uint8_t *data, size_t size)
{
	arc4random_buf(data, size);
}
#else
void
randbytes(uint8_t *data, size_t size)
{
	ssize_t result, ssize = size;

	do result = getrandom(data, size, 0);
	while (ssize != result);
}
#endif

void
randusername(char *username, const char *base)
{
	uint8_t rand[8]; /* -fstack-protector */

	randbytes(rand, 2);
	sprintf(username, "%s%d", base, load16_le(rand));
	crypto_wipe(rand, 2);
}

void
simple_key_exchange(uint8_t shared[32],
		const uint8_t my_prv[32], const uint8_t his_pub[32],
		const uint8_t first_pub[32], const uint8_t second_pub[32])
{
	crypto_blake2b_ctx ctx;

	crypto_x25519(shared, my_prv, his_pub);
	crypto_blake2b_general_init(&ctx, 32, NULL, 0);
	crypto_blake2b_update(&ctx, shared, 32);
	crypto_blake2b_update(&ctx, first_pub, 32);
	crypto_blake2b_update(&ctx, second_pub, 32);
	crypto_blake2b_final(&ctx, shared);
}

void
generate_hidden_keypair(uint8_t hidden[32], uint8_t prv[32])
{
	uint8_t seed[32];
	randbytes(seed, 32);
	crypto_hidden_key_pair(hidden, prv, seed);
	crypto_wipe(seed, 32);
}

void
generate_kex_keypair(uint8_t pub[32], uint8_t prv[32])
{
	randbytes(prv, 32);
	crypto_x25519_public_key(pub, prv);
}

void
generate_sig_keypair(uint8_t pub[32], uint8_t prv[32])
{
	randbytes(prv, 32);
	crypto_sign_public_key(pub, prv);
}

/* BEGIN: these are derived from monocypher directly */
void
store16_le(uint8_t out[2], uint16_t in)
{
	out[0] = (uint8_t)( in        & 0xff);
	out[1] = (uint8_t)((in >>  8) & 0xff);
}

uint16_t
load16_le(const uint8_t s[2])
{
	return (uint16_t)s[0]
	    | ((uint16_t)s[1] <<  8);
}

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

void
store64_le(uint8_t out[8], uint64_t in)
{
	out[0] = (uint8_t)( in        & 0xff);
	out[1] = (uint8_t)((in >>  8) & 0xff);
	out[2] = (uint8_t)((in >> 16) & 0xff);
	out[3] = (uint8_t)((in >> 24) & 0xff);
	out[4] = (uint8_t)((in >> 32) & 0xff);
	out[5] = (uint8_t)((in >> 40) & 0xff);
	out[6] = (uint8_t)((in >> 48) & 0xff);
	out[7] = (uint8_t)((in >> 56) & 0xff);
}

uint64_t
load64_le(const uint8_t s[8])
{
	return (uint64_t)s[0]
	    | ((uint64_t)s[1] <<  8)
	    | ((uint64_t)s[2] << 16)
	    | ((uint64_t)s[3] << 24)
	    | ((uint64_t)s[4] << 32)
	    | ((uint64_t)s[5] << 40)
	    | ((uint64_t)s[6] << 48)
	    | ((uint64_t)s[7] << 56);
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

const char *
errfmt(const char *fmt, ...)
{
	va_list args;
	char *str;
	const char *ret;

	va_start(args, fmt);
	if (-1 == vasprintf(&str, fmt, args)) {
		perror("vasprintf");
		ret = fmt;
	} else ret = str;

	va_end(args);
	return ret;
}

const char *
errwrap(const char *pre, const char *post)
{
	return errfmt("%s: %s", pre, post);
}

const char *
errnowrap(const char *pre)
{
	return errfmt("%s: %m", pre);
}
