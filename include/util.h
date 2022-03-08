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

extern void dumpbytes(const uint8_t *, size_t);
extern void displaykey(const char *, const uint8_t *, size_t);
extern void displaykey_short(const char *, const uint8_t *, size_t);
extern void randbytes(uint8_t *, size_t);
extern void randusername(char *, const char *);
extern void simple_key_exchange(uint8_t shared_key[32],
	const uint8_t my_private_key[32], const uint8_t his_public_key[32],
	const uint8_t first_public_key[32], const uint8_t second_public_key[32]);
extern void generate_hidden_keypair(uint8_t hidden_key[32], uint8_t private_key[32]);
extern void generate_kex_keypair(uint8_t public_key[32], uint8_t private_key[32]);
extern void generate_sig_keypair(uint8_t public_key[32], uint8_t private_key[32]);
/* BEGIN: these are derived from monocypher directly */
extern void store16_le(uint8_t out[2], uint16_t in);
extern uint16_t load16_le(const uint8_t s[2]);
extern void store32_le(uint8_t out[4], uint32_t in);
extern uint32_t load32_le(const uint8_t s[4]);
extern void store64_le(uint8_t out[8], uint64_t in);
extern uint64_t load64_le(const uint8_t s[8]);
/* END: these are derived from monocypher directly */
extern void sign_key(uint8_t sig[64],
	const uint8_t isk_prv[32], const uint8_t isk[32],
	const char name[4], const uint8_t key[32]);
extern int check_key(const uint8_t isk[32], const char name[4],
	const uint8_t key[32], const uint8_t sig[64]);
extern size_t padme(size_t l);
extern size_t floorlog2(size_t x);
extern const char *errnowrap(const char *pre);
extern const char *errwrap(const char *pre, const char *post);
extern const char *errfmt(const char *fmt, ...);
#define container_of(type, member, ptr) (type *)(void *)(((char *)(ptr)) - offsetof(type, member))
