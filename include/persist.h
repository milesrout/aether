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

extern int persist_read(uint8_t **pbuf, size_t *psize, const char *filename, const char *password, size_t password_size);
extern int persist_write(const char *filename, const uint8_t *buf, size_t size, const char *password, size_t password_size);
extern int persist_loadbytes(uint8_t *buf, size_t size, const uint8_t **pbuf, size_t *psize);
extern int persist_load32_le(uint32_t *n, const uint8_t **pbuf, size_t *psize);
extern int persist_loadstr(uint8_t **buf, uint32_t *size, const uint8_t **pbuf, size_t *psize);
extern int persist_storebytes(const uint8_t *buf, size_t size, uint8_t **pbuf, size_t *psize);
extern int persist_store32_le(const uint32_t *n, uint8_t **pbuf, size_t *psize);
extern int persist_storestr(const uint8_t *buf, uint32_t size, uint8_t **pbuf, size_t *psize);
