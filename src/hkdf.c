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

#include <string.h>
#include "monocypher.h"
#include "hkdf.h"

void
hkdf_blake2b(uint8_t *derived_key,   size_t derived_key_size,
		const uint8_t *salt, size_t salt_size,
		const uint8_t *info, size_t info_size,
		const uint8_t *ikm,  size_t ikm_size)
{
	uint8_t prk[64];
	uint8_t *dkptr;

	/* HKDF-Extract */
	crypto_blake2b_general(prk, 64, salt, salt_size, ikm, ikm_size);

	/* HKDF-Expand */
	memcpy(derived_key + derived_key_size, info, info_size);
	derived_key[derived_key_size + info_size] = 0;

	for (dkptr = derived_key + derived_key_size; dkptr > derived_key; dkptr -= 32) {
		/* wrapping overflow of uint8_t is intended */
		derived_key[derived_key_size + info_size]++;
		/* message_size arg is (iterations * 32) + info_size + 1 */
		crypto_blake2b_general(dkptr - 32, 32, prk, 64, dkptr,
			derived_key_size - (dkptr - derived_key) + info_size + 1);
	}

	crypto_wipe(derived_key + derived_key_size, info_size + 1);
	crypto_wipe(prk, 64);
}
