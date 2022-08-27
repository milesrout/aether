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
extern int persist_loadbytes(uint8_t *buf, size_t size, const uint8_t **, size_t *);
extern int persist_loadbytes_ref(const uint8_t **buf, size_t size, const uint8_t **, size_t *);
extern int persist_load8(uint8_t *n, const uint8_t **, size_t *);
extern int persist_load16_le(uint16_t *n, const uint8_t **, size_t *);
extern int persist_load32_le(uint32_t *n, const uint8_t **, size_t *);
extern int persist_load64_le(uint64_t *n, const uint8_t **, size_t *);
extern int persist_loadstr(uint8_t **buf, uint32_t *size, const uint8_t **, size_t *);
extern int persist_loadstr_ref(const uint8_t **pstr, uint32_t *plen, const uint8_t **, size_t *);
extern int persist_storebytes(const uint8_t *buf, size_t size, uint8_t **, size_t *);
extern int persist_store8(uint8_t n, uint8_t **, size_t *);
extern int persist_store16_le(uint16_t n, uint8_t **, size_t *);
extern int persist_store32_le(uint32_t n, uint8_t **, size_t *);
extern int persist_store64_le(uint64_t n, uint8_t **, size_t *);
extern int persist_storestr(const uint8_t *buf, uint32_t size, uint8_t **, size_t *);
extern int persist_zeropad(size_t size, uint8_t **, size_t *);
/* extern int persist_loadbytes    (const uint8_t **, size_t *, uint8_t *buf, size_t size); */
/* extern int persist_loadbytes_ref(const uint8_t **, size_t *, const uint8_t **buf, size_t size); */
/* extern int persist_load8        (const uint8_t **, size_t *, uint8_t *n); */
/* extern int persist_load16_le    (const uint8_t **, size_t *, uint16_t *n); */
/* extern int persist_load32_le    (const uint8_t **, size_t *, uint32_t *n); */
/* extern int persist_load64_le    (const uint8_t **, size_t *, uint64_t *n); */
/* extern int persist_loadstr      (const uint8_t **, size_t *, uint8_t **buf, uint32_t *size); */
/* extern int persist_loadstr_ref  (const uint8_t **, size_t *, const uint8_t **pstr, uint32_t *plen); */
/* extern int persist_storebytes(uint8_t **, size_t *, const uint8_t *buf, size_t size); */
/* extern int persist_store8    (uint8_t **, size_t *, uint8_t n); */
/* extern int persist_store16_le(uint8_t **, size_t *, uint16_t n); */
/* extern int persist_store32_le(uint8_t **, size_t *, uint32_t n); */
/* extern int persist_store64_le(uint8_t **, size_t *, uint64_t n); */
/* extern int persist_storestr  (uint8_t **, size_t *, const uint8_t *buf, uint32_t size); */
/* extern int persist_zeropad   (uint8_t **, size_t *, size_t size); */
