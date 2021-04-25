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
#include "peertable.h"
#include "proof.h"

static const char *progname;

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

static void safe_write(int fd, const uint8_t *buf, size_t size);
static size_t safe_read(int fd, uint8_t *buf, size_t size);
static void usage(void);

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

static
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
		exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Couldn't connect to %s on port %s.\n", addr, port);
	exit(EXIT_FAILURE);
}

static
int
client(int argc, char **argv)
{
	/* TODO: discover through DNS or HTTPS or something */
	/* uint8_t isks[32]; */
	int fd;
	uint8_t iskc[32], iskc_prv[32];
	uint8_t ikc[32], ikc_prv[32];
	struct mesg_state state;
	const char *host, *port;

	if (argc != 4)
		usage();

	host = argv[2];
	port = argv[3];

	generate_sign_keypair(iskc, iskc_prv);
	generate_kex_keypair(ikc, ikc_prv);

	fd = setclientup(host, port);

	{
		uint8_t buf[65536];
		ssize_t nread;

		mesg_hshake_cprepare(&state, isks, iks, iskc, iskc_prv, ikc, ikc_prv);
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
			fprintf(stderr, "Reply message cannot be decrypted.\n");
			crypto_wipe(buf, MESG_REPLY_SIZE);
			return -1;
		}

		crypto_wipe(buf, MESG_REPLY_SIZE);

		memset(MESG_TEXT(buf), 0x77, 24);
		mesg_lock(&state, buf, 24);

		safe_write(fd, buf, MESG_BUF_SIZE(24));
		crypto_wipe(buf, MESG_BUF_SIZE(24));
		fprintf(stderr, "sent 24-byte message\n");

		nread = safe_read(fd, buf, 65536);

		while (nread != -1 && (size_t)nread > MESG_BUF_SIZE(1)) {
			if (mesg_unlock(&state, buf, nread)) {
				break;
			}

			if ((size_t)nread > MESG_BUF_SIZE(1)) {
				mesg_lock(&state, buf, MESG_TEXT_SIZE(nread) - 1);
				safe_write(fd, buf, nread - 1);
				fprintf(stderr, "sent %lu-byte message\n", MESG_TEXT_SIZE(nread) - 1);
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
void
serve(int argc, char **argv)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int fd = -1;
	int gai;
	struct peertable peertable;
	size_t nread;
	uint8_t buf[65536];
	const char *host, *port;

	if (argc != 4)
		usage();

	host = argv[2];
	port = argv[3];

	if (peertable_init(&peertable)) {
		fprintf(stderr, "Couldn't initialise peer table.\n");
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	gai = getaddrinfo(host, port, &hints, &result);
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
		struct peer *peer;
		struct peer_init pi = {0};
		char host[NI_MAXHOST], service[NI_MAXSERV];

		pi.addr_len = sizeof(pi.addr);
		nread = safe_recvfrom(fd, buf, 65536,
			&pi.addr, &pi.addr_len);

		if (!getnameinfo((struct sockaddr *)&pi.addr, pi.addr_len,
				host, NI_MAXHOST,
				service, NI_MAXSERV,
				NI_NUMERICHOST|NI_NUMERICSERV)) {
			fprintf(stderr, "Peer %s on port %s\n",
				host, service);
		} else {
			fprintf(stderr, "Peer on unknown host and port\n");
		}

		fprintf(stderr, "Received %zu bytes. ", nread);

		peer = peer_getbyaddr(&peertable, (struct sockaddr *)&pi.addr, pi.addr_len);
		if (peer == NULL) {
			fprintf(stderr, "Peer not found. ");
			peer = peer_add(&peertable, &pi);
			if (peer == NULL) {
				fprintf(stderr, "Failed to add peer to peertable.\n");
				abort();
			}
		} else {
			fprintf(stderr, "Peer in table. ");
		}

		fprintf(stderr, "Peer status: %d\n", peer->status);

		/* This is either a HELLO message from a new peer or a message
		 * from a peer that isn't new but has just changed addresses
		 * that just happens to be exactly MESG_HELLO_SIZE bytes.
		 */
		if (peer->status == PEER_NEW && nread == MESG_HELLO_SIZE) {
			fprintf(stderr, "This appears to be a HELLO message from a new peer.\n");

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
			 *
			 * Peers that have given a proof of work will be
			 * 'confirmed' and able to roam.  Peers that have not
			 * given a proof of work will be 'unconfirmed', will
			 * not be able to roam, and hopefully will not be able
			 * to do anything that could DOS the server until they
			 * are confirmed.
			 */

			crypto_wipe(&peer->state, sizeof peer->state);

			mesg_hshake_dprepare(&peer->state,
				isks, isks_prv, iks, iks_prv);

			if (!mesg_hshake_dcheck(&peer->state, buf)) {
				crypto_wipe(buf, MESG_HELLO_SIZE);

				mesg_hshake_dreply(&peer->state, buf);
				safe_sendto(fd, buf, MESG_REPLY_SIZE,
					(struct sockaddr *)&peer->addr, peer->addr_len);
				crypto_wipe(buf, MESG_REPLY_SIZE);

				peer->status = PEER_ACTIVE;
				fprintf(stderr, "Peer status: %d\n", peer->status);
				continue;
			}

			fprintf(stderr, "Whoops it wasn't a HELLO... at least not a valid one\n");
			/* Fall through: check if it's a real message */
		}

		if (nread > MESG_BUF_SIZE(0)) {
			if (mesg_unlock(&peer->state, buf, nread)) {
				fprintf(stderr, "Couldn't decrypt message with size=%lu (text_size=%lu)\n",
					nread, MESG_TEXT_SIZE(nread));
				break;
			}
			displaykey("plain", MESG_TEXT(buf), MESG_TEXT_SIZE(nread));

			mesg_lock(&peer->state, buf, MESG_TEXT_SIZE(nread));
			safe_sendto(fd, buf, nread,
				(struct sockaddr *)&pi.addr, pi.addr_len);
			crypto_wipe(buf, nread);

			continue;
		}

		/* It wasn't a valid message at all. */

	}
}

static
void
proof(int argc, char **argv)
{
	uint8_t response[96];
	uint8_t challenge[32];
	uint8_t signing_key[32];
	uint8_t signing_key_prv[32];
	uint8_t difficulty = 26;

	(void)argv;

	if (argc != 2)
		usage();

	randbytes(challenge, 32);
	randbytes(signing_key_prv, 32);
	crypto_sign_public_key(signing_key, signing_key_prv);

	displaykey("challenge", challenge, 32);
	displaykey("public key", signing_key, 32);
	displaykey("private key", signing_key_prv, 32);

	proof_solve(response, challenge, signing_key, signing_key_prv, difficulty);

	if (proof_check(response, challenge, signing_key, difficulty))
		fprintf(stderr, "Could not verify challenge response.\n");
	else
		fprintf(stderr, "Verified proof of work.\n");
}

static
void
keygen(int argc, char **argv)
{
	uint8_t pub[32], prv[32];

	(void)argv;

	if (argc != 2)
		usage();

	generate_kex_keypair(pub, prv);

	displaykey("pub", pub, 32);
	displaykey("prv", prv, 32);
}

static
void
usage(void)
{
	fprintf(stderr, "usage: %s (k[eygen] | p[roof] | c[lient] HOST PORT | d[aemon) HOST PORT)\n",
		progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	progname = argv[0];

	if (argc < 2)
		usage();

	switch (argv[1][0]) {
		case 'k': keygen(argc, argv); break;
		case 'p': proof(argc, argv); break;
		case 'c': client(argc, argv); break;
		case 'd': serve(argc, argv); break;
		default:  usage();
	}

	return 0;
}
