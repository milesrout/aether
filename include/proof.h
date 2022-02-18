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

extern void proof_create(uint8_t challenge[32]);
extern int proof_check(
	const uint8_t response[96],
	const uint8_t challenge[32],
	const uint8_t signing_key[32],
	uint8_t difficulty);
extern void proof_solve(
	uint8_t response[96],
	const uint8_t challenge[32],
	const uint8_t signing_key[32],
	const uint8_t signing_key_prv[32],
	uint8_t difficulty);
