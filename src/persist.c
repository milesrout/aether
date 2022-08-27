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

#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

#include "monocypher.h"

#include "err.h"
#include "persist.h"
#include "util.h"

#define ARGON2I_ITERATIONS 3
#ifdef BUILD_VALGRIND
#define ARGON2I_BLOCKS 100
#else
#define ARGON2I_BLOCKS 100000
#endif
#define ARGON2I_BLOCK_SIZE 1024

#define NONCE_SIZE 24
#define MAC_SIZE 16
#define SALT_SIZE 16
#define PERSIST_OVERHEAD (NONCE_SIZE + MAC_SIZE + SALT_SIZE)
#define TEXT_OFFSET (NONCE_SIZE + SALT_SIZE)

static
void
hash_password(uint8_t key[32], const uint8_t salt[16],
	const char *password, size_t password_size);

int
persist_read(uint8_t **pbuf, size_t *psize, const char *filename,
		const char *password, size_t password_size)
{
	int fd = -1, result = -1;
	off_t off = 0;
	size_t size = 0;
	void *file = MAP_FAILED, *buf = MAP_FAILED;
	uint8_t key[32];

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		errg(cleanup, "Could not open `%s'", filename);

	off = lseek(fd, 0, SEEK_END);
	if (off == -1)
		errg(cleanup, "Could not seek `%s'", filename);

	if (off <= PERSIST_OVERHEAD)
		errg(cleanup, "File too small `%s'", filename);

	size = off - PERSIST_OVERHEAD;

	file = mmap(NULL, off, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED)
		errg(cleanup, "Could not map `%s'", filename);

	hash_password(key, (uint8_t *)file, password, password_size);

	buf = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED)
		errg(cleanup, "Could not map %ld bytes of memory", off);

	if (mlock(buf, size))
		errg(cleanup, "Could not lock %ld bytes of memory", off);

	if (crypto_unlock(
			(uint8_t *)buf,                   /* plain */
			key,                              /* key */
			(uint8_t *)file + SALT_SIZE,      /* nonce */
			(uint8_t *)file + off - MAC_SIZE, /* mac */
			(uint8_t *)file + TEXT_OFFSET,    /* cipher */
			size))                            /* size */
		errg(cleanup, "Could not decrypt `%s'", filename);

	result = 0;
	*pbuf = buf;
	*psize = size;

cleanup:
	crypto_wipe(key, 32);
	if (result && buf != MAP_FAILED) munmap(buf, off);
	if (file != MAP_FAILED) munmap(file, off);
	if (fd != -1) close(fd);
	return result;
}

int
persist_write(const char *filename, const uint8_t *buf, size_t size,
		const char *password, size_t password_size)
{
	int fd = -1, result = -1;
	void *file = MAP_FAILED;
	size_t total = size + PERSIST_OVERHEAD;
	uint8_t key[32];

	fd = open(filename, O_CREAT|O_RDWR, 0600);
	if (fd == -1)
		errg(cleanup, "Could not open `%s'", filename);

	if (ftruncate(fd, total))
		errg(cleanup, "Could not resize `%s' to `%lu'",
			filename, total);

	file = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (file == MAP_FAILED)
		errg(cleanup, "Could not map `%s'", filename);

	randbytes(file, SALT_SIZE + NONCE_SIZE);

	hash_password(key, (uint8_t *)file, password, password_size);

	crypto_lock((uint8_t *)file + total - MAC_SIZE, /* mac */
		(uint8_t *)file + TEXT_OFFSET,          /* cipher */
		key,                                    /* key */
		(uint8_t *)file + SALT_SIZE,            /* nonce */
		(const uint8_t *)buf,                   /* plain */
		size);                                  /* size */
	result = 0;

cleanup:
	crypto_wipe(key, 32);
	if (file != MAP_FAILED) munmap(file, total);
	if (fd != -1) close(fd);
	return result;
}

static
void
hash_password(uint8_t key[32], const uint8_t salt[16], const char *password, size_t password_size)
{
	uint8_t *work_area = calloc(ARGON2I_BLOCK_SIZE, ARGON2I_BLOCKS);
	if (work_area == NULL)
		err(1, "Could not allocate memory for Argon2i work area");

	crypto_argon2i(
		key, 32,
		work_area, ARGON2I_BLOCKS, ARGON2I_ITERATIONS,
		(const uint8_t *)password, password_size,
		salt, SALT_SIZE);

	free(work_area);
}

int
persist_loadbytes_ref(const uint8_t **buf, size_t size, const uint8_t **pbuf, size_t *psize)
{
	if (*psize < size)
		return -1;

	*buf = *pbuf;

	*pbuf += size;
	*psize -= size;

	return 0;
}

int
persist_loadbytes(uint8_t *buf, size_t size, const uint8_t **pbuf, size_t *psize)
{
	if (*psize < size)
		return -1;

	memcpy(buf, *pbuf, size);

	*pbuf += size;
	*psize -= size;

	return 0;
}

int
persist_load8(uint8_t *n, const uint8_t **pbuf, size_t *psize)
{
	if (*psize < 1)
		return -1;

	*n = *(*pbuf)++;
	(*psize)--;

	return 0;
}

int
persist_load16_le(uint16_t *n, const uint8_t **pbuf, size_t *psize)
{
	if (*psize < 2)
		return -1;

	*n = load16_le(*pbuf);

	*pbuf += 2;
	*psize -= 2;

	return 0;
}

int
persist_load32_le(uint32_t *n, const uint8_t **pbuf, size_t *psize)
{
	if (*psize < 4)
		return -1;

	*n = load32_le(*pbuf);

	*pbuf += 4;
	*psize -= 4;

	return 0;
}

int
persist_load64_le(uint64_t *n, const uint8_t **pbuf, size_t *psize)
{
	if (*psize < 8)
		return -1;

	*n = load64_le(*pbuf);

	*pbuf += 8;
	*psize -= 8;

	return 0;
}

int
persist_loadstr_ref(const uint8_t **pstr, uint32_t *plen, const uint8_t **pbuf, size_t *psize)
{
	const uint8_t *buf, *str;
	uint32_t len;
	size_t size;
	int result;

	buf = *pbuf;
	size = *psize;

	/* result is an unused variable in release mode (asserts disabled) */
	(void)result;
	if (persist_load32_le(&len, &buf, &size)) return -1;
	if (*psize < len) return -1;

	result = persist_loadbytes_ref(&str, len, &buf, &size);
	assert(result == 0);
	if (str[len] != '\0') return -1;

	*pbuf = buf;
	*psize = size;
	*pstr = str;
	if (plen)
		*plen = len;
	return 0;
}

int
persist_loadstr(uint8_t **pstr, uint32_t *plen, const uint8_t **pbuf, size_t *psize)
{
	uint32_t len;
	int result;
	char *str;
	const uint8_t *buf;
	size_t size;

	buf = *pbuf;
	size = *psize;

	/* result is an unused variable in release mode (asserts disabled) */
	(void)result;
	if (persist_load32_le(&len, &buf, &size)) return -1;
	if (*psize < len) return -1;

	str = malloc(len + 1);
	if (!str) return -1;

	result = persist_loadbytes(str, len, &buf, &size);
	assert(result == 0);
	str[len] = '\0';

	*pbuf = buf;
	*psize = size;
	*pstr = str;
	if (plen)
		*plen = len;
	return 0;
}

int
persist_storebytes(const uint8_t *buf, size_t size, uint8_t **pbuf, size_t *psize)
{
	if (*psize < size)
		return -1;

	memcpy(*pbuf, buf, size);

	*pbuf += size;
	*psize -= size;

	return 0;
}

int
persist_store8(uint8_t n, uint8_t **pbuf, size_t *psize)
{
	if (*psize < 1)
		return -1;

	*(*pbuf)++ = n;
	*psize -= 1;

	return 0;
}

int
persist_store16_le(uint16_t n, uint8_t **pbuf, size_t *psize)
{
	if (*psize < 2)
		return -1;

	store16_le(*pbuf, n);

	*pbuf += 2;
	*psize -= 2;

	return 0;
}

int
persist_store32_le(uint32_t n, uint8_t **pbuf, size_t *psize)
{
	if (*psize < 4)
		return -1;

	store32_le(*pbuf, n);

	*pbuf += 4;
	*psize -= 4;

	return 0;
}

int
persist_store64_le(uint64_t n, uint8_t **pbuf, size_t *psize)
{
	if (*psize < 8)
		return -1;

	store64_le(*pbuf, n);

	*pbuf += 8;
	*psize -= 8;

	return 0;
}

int
persist_storestr(const uint8_t *buf, uint32_t size, uint8_t **pbuf, size_t *psize)
{
	if (persist_store32_le(size, pbuf, psize)) return -1;
	if (persist_storebytes(buf, size, pbuf, psize)) return -1;
	return 0;
}

int
persist_zeropad(size_t size, uint8_t **pbuf, size_t *psize)
{
	if (*psize < size)
		return -1;

	memset(*pbuf, 0, size);

	*pbuf += size;
	*psize -= size;

	return 0;
}
