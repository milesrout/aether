#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "monocypher.h"

#include "err.h"
#include "persist.h"
#include "util.h"

int persist_read(uint8_t **pbuf, size_t *psize, const char *filename,
		const uint8_t key[32])
{
	int fd = -1, result = -1;
	off_t off = 0;
	size_t size = 0;
	void *file = MAP_FAILED, *buf = MAP_FAILED;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		errg(cleanup, "Could not open `%s'", filename);

	off = lseek(fd, 0, SEEK_END);
	if (off == -1)
		errg(cleanup, "Could not seek `%s'", filename);

	if (off <= 40)
		errg(cleanup, "File too small `%s'", filename);

	size = off - 40;

	file = mmap(NULL, off, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED)
		errg(cleanup, "Could not map `%s'", filename);

	buf = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED)
		errg(cleanup, "Could not map %ld bytes of memory", off);

	if (mlock(buf, size))
		errg(cleanup, "Could not lock %ld bytes of memory", off);

	if (crypto_unlock(
			(uint8_t *)buf,             /* plain */
			key,                        /* key */
			(uint8_t *)file,            /* nonce */
			(uint8_t *)file + off - 16, /* mac */
			(uint8_t *)file + 24,       /* cipher */
			size))                      /* size */
		errg(cleanup, "Could not decrypt `%s'", filename);

	result = 0;
	*pbuf = buf;
	*psize = size;

cleanup:
	if (result && buf != MAP_FAILED) munmap(buf, off);
	if (file != MAP_FAILED) munmap(file, off);
	if (fd != -1) close(fd);
	return result;
}

int persist_write(const char *filename, const uint8_t *buf, size_t size,
		const uint8_t key[32])
{
	int fd = -1, result = -1;
	void *file = MAP_FAILED;
	size_t total = size + 40;

	fd = open(filename, O_CREAT|O_RDWR, 0600);
	if (fd == -1)
		errg(cleanup, "Could not open `%s'", filename);

	if (ftruncate(fd, total))
		errg(cleanup, "Could not resize `%s' to `%lu'",
			filename, total);

	file = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (file == MAP_FAILED)
		errg(cleanup, "Could not map `%s'", filename);

	randbytes(file, 24);
	crypto_lock((uint8_t *)file + total - 16, /* mac */
		(uint8_t *)file + 24,             /* cipher */
		key,                              /* key */
		(uint8_t *)file,                  /* nonce */
		(const uint8_t *)buf,             /* plain */
		size);                            /* size */
	result = 0;

cleanup:
	if (file != MAP_FAILED) munmap(file, total);
	if (fd != -1) close(fd);
	return result;
}
