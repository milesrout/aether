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

/* RFC 5869 HKDF with Hash=BLAKE2b but please note the
 * additional (unchecked) requirements.
 *
 * Derived_key_size MUST be a multiple of 32.
 * MOST IMPORTANTLY, derived_key must point to a buffer that
 * can contain at least derived_key_size + info_size + 1.
 * After this function it will contain the derived_key of the
 * desired size and then info_size + 1 zeroes.
 * There are reasonable size limits on the inputs too.
 * (Also please read the whole RFC.  It's not very long.)
 *
 * hkdf_blake2b wipes its own internal buffers, but not the salt or info.
 * crypto_wipe is your friend. :)
 */
extern void hkdf_blake2b(uint8_t *derived_key, size_t derived_key_size,
		const uint8_t *salt, size_t salt_size,
		const uint8_t *info, size_t info_size,
		const uint8_t *ikm,  size_t ikm_size);
