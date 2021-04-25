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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "util.h"
#include "proof.h"

#define WORKAREA (100 * 1024)
#define ITERATIONS 3

/* Proof of work.  A proof of work is created by just generating 64 random
 * bytes.  These bytes are called the challenge.  These bytes are sent to a
 * client, who then must do some work to generate the result we want.
 *
 * The result we want is a hash of the challenge, specifically one with a
 * particular number of initial zero bytes.  The number of initial zero bytes
 * determines the difficulty of the challenge, along with the other parameters
 * of the hash function.
 */

void
proof_create(uint8_t challenge[64])
{
	randbytes(challenge, 64);
}

static
int
check_zero_prefix(const uint8_t hash[64], uint8_t difficulty)
{
	int i;

	for (i = 0; i < difficulty; i++) {
		if ((hash[i / 8] >> (i % 8) & 1)) {
			return -1;
		}
	}

	return 0;
}

int
proof_check(const uint8_t response[96], const uint8_t challenge[64],
		const uint8_t signing_key[32], uint8_t difficulty)
{
	uint8_t hash[64];
	uint8_t *workarea = NULL;
	uint8_t challenge_and_salt[96];
	int result = -1;

	memcpy(challenge_and_salt,      challenge,     64);
	memcpy(challenge_and_salt + 64, response + 64, 32);
	displaykey("challenge_and_salt (recv'd)", challenge_and_salt, 96);

	if (crypto_check(response, signing_key, challenge_and_salt, 96)) {
		fprintf(stderr, "Failed signature\n");
		goto end;
	}

	workarea = malloc(WORKAREA * 1024);
	crypto_argon2i(
		hash, 64,            /* hash output */
		workarea, WORKAREA,  /* work area for memory hardness */
		ITERATIONS,          /* number of iterations */
		challenge, 64,       /* challenge value */
		response + 64, 32);  /* client's proof of work */

	result = check_zero_prefix(hash, difficulty);
	displaykey("hash", hash, 64);
	if (result)
		fprintf(stderr, "Failed zero prefix\n");

end:
	if (workarea)
		free(workarea);
	crypto_wipe(hash, 64);

	return result;
}

static
void
increment(uint8_t value[32])
{
	uint64_t a = load64_le(value);
	uint64_t b = load64_le(value + 8);
	uint64_t c = load64_le(value + 16);
	uint64_t d = load64_le(value + 24);

	a++;
	if (a == 0) {
		b++;
		if (b == 0) {
			c++;
			if (c == 0)
				d++;
		}
	}

	store64_le(value,      a);
	store64_le(value + 8,  b);
	store64_le(value + 16, c);
	store64_le(value + 24, d);
}

void
proof_solve(uint8_t response[96], const uint8_t challenge[64],
	const uint8_t signing_key[32], const uint8_t signing_key_prv[32],
	uint8_t difficulty)
{
	uint8_t salt[32];
	uint8_t hash[64];
	uint8_t *workarea = malloc(100 * 1024 * 1024);

	crypto_wipe(response, 96);
	crypto_wipe(salt, 32);

	displaykey("salt", salt, 32);

	crypto_argon2i(
		hash, 64,		/* hash output */
		workarea, WORKAREA,	/* work area for memory hardness */
		ITERATIONS,		/* number of iterations */
		challenge, 64,		/* challenge value */
		salt, 32);		/* client's proof of work */
	displaykey("hash", hash, 64);

	while (check_zero_prefix(hash, difficulty)) {
		increment(salt);
		fprintf(stderr, "\033[F\033[F\033[F\033[F");
		displaykey("salt", salt, 32);

		crypto_argon2i(
			hash, 64,		/* hash output */
			workarea, WORKAREA,	/* work area for memory hardness */
			ITERATIONS,		/* number of iterations */
			challenge, 64,		/* challenge value */
			salt, 32);		/* client's proof of work */
		displaykey("hash", hash, 64);
	}

	{
		uint8_t challenge_and_salt[96];
		memcpy(challenge_and_salt,      challenge, 64);
		memcpy(challenge_and_salt + 64, salt,      32);
		displaykey("challenge_and_salt (to sign)", challenge_and_salt, 96);
		crypto_sign(response, signing_key_prv, signing_key, challenge_and_salt, 96);
		memcpy(response + 64, salt, 32);
		displaykey("response (signature || salt)", response, 96);
	}
}
