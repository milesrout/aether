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
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "err.h"
#include "fibre.h"
#include "io.h"
#include "util.h"
#include "queue.h"
#include "packet.h"

int
setclientup(const char *addr, const char *port)
{
	struct addrinfo hints, *result, *rp;
	int fd = -1, gai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	gai = getaddrinfo(addr, port, &hints, &result);
	if (gai != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, SOCK_NONBLOCK|rp->ai_socktype,
			rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
			freeaddrinfo(result);
			return fd;
		}

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		fprintf(stderr, "Couldn't bind to socket.\n");
		return -1;
	}

	fprintf(stderr, "Couldn't connect to %s on port %s.\n", addr, port);
	return -1;
}

int
fcntl_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		err(1, "fcntl_nonblock: fcntl(F_GETFL)");

	if (fcntl(fd, F_SETFL, flags|O_NONBLOCK))
		err(1, "fcntl_nonblock: fcntl(F_SETFL)");

	return 0;
}

const char *
safe_read(size_t *nread, int fd, uint8_t *buf, size_t size)
{
	ssize_t n;

	do n = fibre_read(fd, buf, size);
	while (n == -1 && errno == EINTR);

	if (n == -1)
		return errnowrap("read");
	
	*nread = n;
	return NULL;
}

const char *
safe_recvfrom(size_t *nread, int fd, uint8_t *buf, size_t size,
		struct sockaddr *peeraddr, socklen_t *peeraddr_len)
{
	ssize_t n;

	do {
		*peeraddr_len = sizeof(struct sockaddr_storage);
		n = fibre_recvfrom(fd, buf, size, 0,
			peeraddr, peeraddr_len);
	} while (n == -1 && errno == EINTR);
	if (n == -1)
		return errnowrap("recvfrom");

	*nread = n;
	return NULL;
}

const char *
safe_write(int fd, const uint8_t *buf, size_t size)
{
	ssize_t result;

	do result = fibre_write(fd, buf, size);
	while (result == -1 && errno == EINTR);
	if (result == -1)
		return errnowrap("write");

	return NULL;
}

const char *
safe_sendto(int fd, const uint8_t *buf, size_t size,
		struct sockaddr *peeraddr, socklen_t peeraddr_len)
{
	ssize_t result;

	do result = fibre_sendto(fd, buf, size, 0, peeraddr, peeraddr_len);
	while (result == -1 && errno == EINTR);
	if (result == -1)
		return errnowrap("sendto");

	return NULL;
}
