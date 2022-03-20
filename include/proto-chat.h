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

#define PROTO_CHAT ((uint8_t)3)
#define CHAT_NACK ((uint8_t)1)
#define CHAT_FORWARD_MSG ((uint8_t)2)
#define CHAT_FORWARD_ACK ((uint8_t)3)
#define CHAT_FETCH_MSG ((uint8_t)4)
#define CHAT_FETCH_REP ((uint8_t)5)
#define CHAT_IMMEDIATE ((uint8_t)6)
#define CHAT_GOODBYE_MSG ((uint8_t)8)
#define CHAT_GOODBYE_ACK ((uint8_t)9)
