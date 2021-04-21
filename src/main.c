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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#include "monocypher.h"
#include "hkdf.h"
#include "util.h"
#include "mesg.h"

/* A note on terminology.
 *
 * I have tried to use terminology that is as consistent as possible.  Alas, I
 * have not always succeeded.  Here are some terms that might seem like
 * synonyms that I have tried to consistently distinguish:
 *
 * private key: exclusively refers to the _unshared_ half of an asymmetric keypair.
 * vs.
 * secret key: exclusively refers to _shared_ secret keys.
 */

/* types */
/* debugging */
static void printhexbytes(const uint8_t *data, size_t size);
static void displaykey(const char *name, const uint8_t *key, size_t size);

/* real functions */

static void safe_write(int fd, const uint8_t *buf, size_t size);
static size_t safe_read(int fd, uint8_t *buf, size_t size);
static int setclientup(const char *addr, const char *port);

static
void
printhexbytes(const uint8_t *data, size_t size)
{
	while (size--)
		fprintf(stderr, "%02x", *data++);
}

static
void
displaykey(const char *name, const uint8_t *key, size_t size)
{
	/*printf("%s:\n", name);*/
	printhexbytes(key, size);
	putchar('\n');
}

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

struct ra_init_msg {
	uint8_t ikc[32];     /* client's identity key */
};

union mesgbuf {
	uint8_t buf[65536];
	struct mesg mesg;
};

static
int
client(const char *addr, const char *port)
{
	/* TODO: discover through DNS or HTTPS or something */
	/* uint8_t isks[32]; */
	int fd;
	int FLAG_TESTING_ONLY_1 = 0;
	int FLAG_TESTING_ONLY_2 = 0;
	ssize_t nread;
	uint8_t iskc[32], iskc_prv[32];
	uint8_t ikc[32], ikc_prv[32];
	struct mesg_state state;

	generate_sign_keypair(iskc, iskc_prv);
	generate_kex_keypair(ikc, ikc_prv);

	fd = setclientup(addr, port);

	{
		uint8_t buf[MESG_HSHAKE_SIZE + 1];

		mesg_hshake_cprepare(&state, isks, iskc, iskc_prv, ikc, ikc_prv);
		mesg_hshake_chello(&state, buf);
		safe_write(fd, buf, MESG_HELLO_SIZE);
		crypto_wipe(buf, MESG_HELLO_SIZE);

		nread = safe_read(fd, buf, MESG_REPLY_SIZE + 1);
		if (nread != MESG_REPLY_SIZE) {
			fprintf(stderr, "Received the wrong message.\n");
			crypto_wipe(buf, MESG_REPLY_SIZE);
			return -1;
		}

		if (mesg_hshake_cfinish(&state, buf)) {
			crypto_wipe(buf, MESG_REPLY_SIZE);
			return -1;
		}

		crypto_wipe(buf, MESG_REPLY_SIZE);
	}

	{
		uint8_t buf1[MESG_BUF_SIZE(256)];
		uint8_t buf2[MESG_BUF_SIZE(128)];
		uint8_t buf3[MESG_BUF_SIZE(1024)];
		uint8_t buf[65536];
		ssize_t nread;

		memset(MESG_TEXT(buf1), 0x55, 256);
		mesg_lock(&state, buf1, 256);

		memset(MESG_TEXT(buf2), 0x77, 128);
		mesg_lock(&state, buf2, 128);

		memset(MESG_TEXT(buf3), 0x99, 1024);
		mesg_lock(&state, buf3, 1024);

		safe_write(fd, buf3, MESG_BUF_SIZE(1024));
		crypto_wipe(buf3, MESG_BUF_SIZE(1024));
		fprintf(stderr, "sent 1024-byte message\n");

		safe_write(fd, buf2, MESG_BUF_SIZE(128));
		crypto_wipe(buf2, MESG_BUF_SIZE(128));
		fprintf(stderr, "sent 128-byte message\n");

		nread = safe_read(fd, buf, 65536);
		if (mesg_unlock(&state, buf, nread))
			abort();
		displaykey("reply from server", MESG_TEXT(buf), MESG_TEXT_SIZE(nread));
		crypto_wipe(buf, nread);

		safe_write(fd, buf1, MESG_BUF_SIZE(256));
		crypto_wipe(buf1, MESG_BUF_SIZE(256));
		fprintf(stderr, "sent 256-byte message\n");

	}

	{
		uint8_t buf[65536];
		ssize_t nread = safe_read(fd, buf, 65536);
		int which = 0;

		while (nread != -1 && (size_t)nread > MESG_BUF_SIZE(0)) {
			which = which ? 0 : 1;
			if (mesg_unlock(&state, buf, nread)) {
				break;
			}

			if (which ? FLAG_TESTING_ONLY_1 : FLAG_TESTING_ONLY_2) {
				mesg_lock(&state, buf, MESG_TEXT_SIZE(nread) + (which ? 1 : 2));
				safe_write(fd, buf, nread + (which ? 1 : 2));
				fprintf(stderr, "sent %ld-byte message\n", nread + (which ? 1 : 2));
			} else {
				mesg_lock(&state, buf, MESG_TEXT_SIZE(nread) - (which ? 1 : 2));
				safe_write(fd, buf, nread - (which ? 1 : 2));
				fprintf(stderr, "sent %ld-byte message\n", nread - (which ? 1 : 2));
			}

			if (nread < 101) {
				if (which)
					FLAG_TESTING_ONLY_1 = 1;
				else
					FLAG_TESTING_ONLY_2 = 1;
			}

			if (nread > 199) {
				if (which)
					FLAG_TESTING_ONLY_1 = 0;
				else
					FLAG_TESTING_ONLY_2 = 0;
			}

			crypto_wipe(buf, 65536);

			nread = safe_read(fd, buf, 65536);
		}
	}

	exit(EXIT_FAILURE);
}

/* the following functions are "safe" in the sense that instead of returning an
 * error, they abort the program.  They are not safe in the sense that they
 * cannot produce errors or in the sense that they can be used with impunity.
 */
static
size_t
safe_read(int fd, uint8_t *buf, size_t max_size_p1)
{
	ssize_t nread;

	do nread = read(fd, buf, max_size_p1);
	while (nread == -1 && errno == EINTR);

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

static
size_t
safe_recvfrom(int fd, uint8_t *buf, size_t max_size_p1,
		struct sockaddr_storage *peeraddr, socklen_t *peeraddr_len)
{
	ssize_t nread;

	do {
		*peeraddr_len = sizeof(peeraddr);
		nread = recvfrom(fd, buf, max_size_p1, 0,
			(struct sockaddr *)peeraddr, peeraddr_len);
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

static
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

static
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

static
int
setclientup(const char *addr, const char *port)
{
	struct addrinfo hints, *result, *rp;
	int fd = -1, gai;
	/*
	ssize_t nread;
	char buf[128];
	*/

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	gai = getaddrinfo(addr, port, &hints, &result);
	if (gai != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		exit(EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			return fd;

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		fprintf(stderr, "Couldn't bind to socket.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Couldn't connect to %s on port %s.\n", addr, port);
	exit(EXIT_FAILURE);

	/*
	for (;;) {
		nread = write(fd, buf, 128);
		if (nread == 128)
			continue;

		fprintf(stderr, "Received %zd bytes.\n", nread);
	}
	*/
}

static
void
serve(const char *addr, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int fd = -1;
	int FLAG_TESTING_ONLY = 0;
	int gai;
	struct sockaddr_storage peeraddr;
	socklen_t peeraddr_len;
	ssize_t nread;
	uint8_t buf[65536];
	uint8_t iks[32], iks_prv[32];
	struct mesg_state state;

	generate_kex_keypair(iks, iks_prv);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	gai = getaddrinfo(addr, port, &hints, &result);
	if (gai != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		exit(EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		fprintf(stderr, "Couldn't bind to socket.\n");
		exit(EXIT_FAILURE);
	}

	for (;;) {
		peeraddr_len = sizeof(peeraddr);
		nread = safe_recvfrom(fd, buf, 65536,
			&peeraddr, &peeraddr_len);

		/*fprintf(stderr, "Received %zd bytes.\n", nread);*/
		if (FLAG_TESTING_ONLY == 0 && nread == MESG_HELLO_SIZE) {
			FLAG_TESTING_ONLY = 1;
			/* TODO: Proof of work - to prevent denial of service:
			 * The server should require that the client does some
			 * proof-of-work task in order to initiate a connection.
			 * This task should be both memory-hard and time-hard
			 * for the client but easy to verify for the server.
			 *
			 * The hardness of the task could be altered based on:
			 * - current server load
			 * - trustworthiness of the client (after identity
			 *   verification)
			 * - niceness of the client (how much they load the
			 *   server and how much they're loading the server at
			 *   the moment)
			 * - any other relevant factors
			 */

			mesg_hshake_dprepare(&state,
				isks, isks_prv, iks, iks_prv);

			if (mesg_hshake_dcheck(&state, buf)) {
				crypto_wipe(buf, MESG_HELLO_SIZE);
				continue;
			}
			crypto_wipe(buf, MESG_HELLO_SIZE);

			mesg_hshake_dreply(&state, buf);

			safe_sendto(fd, buf, MESG_REPLY_SIZE,
				(struct sockaddr *)&peeraddr, peeraddr_len);
			crypto_wipe(buf, MESG_REPLY_SIZE);
		} else if (nread != -1 && (size_t)nread > MESG_BUF_SIZE(0)) {
			if (mesg_unlock(&state, buf, nread)) {
				fprintf(stderr, "Couldn't decrypt message with size=%ld (text_size=%lu)\n",
					nread, MESG_TEXT_SIZE(nread));
				break;
			}
			/*fprintf(stderr, "Decrypted message with size=%ld (text_size=%lu)\n",
				nread, MESG_TEXT_SIZE(nread));*/
			displaykey("plain", MESG_TEXT(buf), MESG_TEXT_SIZE(nread));

			mesg_lock(&state, buf, MESG_TEXT_SIZE(nread));
			safe_sendto(fd, buf, nread,
				(struct sockaddr *)&peeraddr, peeraddr_len);
			crypto_wipe(buf, nread);
			/*fprintf(stderr, "Encrypted and sent message with size=%ld (text_size=%lu)\n",
				nread, MESG_TEXT_SIZE(nread));*/

		}
	}
}

static
void
usage(const char *prog)
{
	fprintf(stderr, "usage: %s HOST PORT (c[lient] | d[aemon))\n", prog);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	const char *host, *port;

	if (argc != 4) 
		usage(argv[0]);

	host = argv[1];
	port = argv[2];

	switch (argv[3][0]) {
		case 'c': client(host, port); break;
		case 'd': serve(host, port); break;
		default:  usage(argv[0]);
	}

	return 0;
}
