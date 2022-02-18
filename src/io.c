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

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "io.h"

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
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
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


struct sockaddr *
sstosa(struct sockaddr_storage *ss)
{
	return (struct sockaddr *)ss;
}

size_t
safe_read(int fd, uint8_t *buf, size_t max_size_p1)
{
	ssize_t nread;

	do nread = read(fd, buf, max_size_p1);
	while (nread == -1 && errno == EINTR);

	if (nread == -1) {
		fprintf(stderr, "Error while reading from socket (%d).\n", errno);
		exit(EXIT_FAILURE);
	}
	if ((size_t)nread == max_size_p1) {
		fprintf(stderr, "Peer sent a packet that is too large.\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

size_t
safe_read_nonblock(int fd, uint8_t *buf, size_t max_size_p1)
{
	ssize_t nread;

	do nread = recv(fd, buf, max_size_p1, MSG_DONTWAIT);
	while (nread == -1 && errno == EINTR);

	if (nread == -1 && errno == EAGAIN) {
		return 0;
	}
	if (nread == -1) {
		fprintf(stderr, "Error while reading from socket (%d).\n", errno);
		exit(EXIT_FAILURE);
	}
	if ((size_t)nread == max_size_p1) {
		fprintf(stderr, "Peer sent a packet that is too large.\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

size_t
safe_read_timeout(int fd, uint8_t *buf, size_t max_size_p1, time_t timeout)
{
	struct timeval tv = { .tv_sec = timeout, .tv_usec = 0 };
	ssize_t nread;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

	do nread = recv(fd, buf, max_size_p1, 0);
	while (nread == -1 && errno == EINTR);

	tv.tv_sec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

	if (nread == -1 && errno == EAGAIN) {
		return 0;
	}
	if (nread == -1) {
		fprintf(stderr, "Error while reading from socket (%d).\n", errno);
		exit(EXIT_FAILURE);
	}
	if ((size_t)nread == max_size_p1) {
		fprintf(stderr, "Peer sent a packet that is too large.\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

size_t
safe_recvfrom(int fd, uint8_t *buf, size_t max_size_p1,
		struct sockaddr_storage *peeraddr, socklen_t *peeraddr_len)
{
	ssize_t nread;

	do {
		*peeraddr_len = sizeof(peeraddr);
		nread = recvfrom(fd, buf, max_size_p1, 0,
			sstosa(peeraddr), peeraddr_len);
	} while (nread == -1 && errno == EINTR);

	if (nread == -1) {
		fprintf(stderr, "Error while reading from socket.\n");
		exit(EXIT_FAILURE);
	}
	if ((size_t)nread == max_size_p1) {
		fprintf(stderr, "Peer sent a packet that is too large.\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

void
safe_write(int fd, const uint8_t *buf, size_t size)
{
	ssize_t result;

	result = write(fd, buf, size);
	while (result == -1 || (size_t)result < size) {
		if (result == -1 && errno == EINTR) {
			result = write(fd, buf, size);
			continue;
		}
		if (result == -1) {
			fprintf(stderr, "Error while writing to socket.\n");
			exit(EXIT_FAILURE);
		}
		buf += result;
		size -= result;
		result = write(fd, buf, size);
	}
}

void
safe_sendto(int fd, const uint8_t *buf, size_t size, struct sockaddr *peeraddr, socklen_t peeraddr_len)
{
	ssize_t result;

	result = sendto(fd, buf, size, 0, peeraddr, peeraddr_len);
	while (result == -1 || (size_t)result < size) {
		if (result == -1 && errno == EINTR) {
			result = sendto(fd, buf, size, 0, peeraddr, peeraddr_len);
			continue;
		}
		if (result == -1) {
			fprintf(stderr, "Error while writing to socket.\n");
			exit(EXIT_FAILURE);
		}
		buf += result;
		size -= result;
		result = sendto(fd, buf, size, 0, peeraddr, peeraddr_len);
	}
}
