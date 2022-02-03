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
#include "ident.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

static const char *progname;

/* A note on terminology.
 *
 * I have tried to use terminology that is as consistent as possible.  Alas, I
 * have not always succeeded.  Here are some terms that might seem like
 * synonyms that I have tried to consistently distinguish:
 *
 * private key: exclusively refers to the _unshared_ half of an asymmetric keypair.
 * vs.
 * secret key: exclusively refers to _symmetric_ secret keys.
 */

static void safe_write(int fd, const uint8_t *buf, size_t size);
static size_t safe_read(int fd, uint8_t *buf, size_t size);
static size_t safe_read_nonblock(int fd, uint8_t *buf, size_t size);
static int handle_replies(int fd, uint8_t buf[65536], struct mesg_state *state, int minreplies);
static void usage(void);

static
struct sockaddr *
sstosa(struct sockaddr_storage *ss)
{
	return (struct sockaddr *)ss;
}

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
alice(int argc, char **argv)
{
	int fd;
	uint8_t iska[32], iska_prv[32];
	uint8_t ika[32], ika_prv[32];
	uint8_t iskb[32], ikb[32], spkb[32], opkb[32];
	uint8_t ikb_sig[64], spkb_sig[64];
	struct mesg_state state;
	struct mesg_state p2pstate;
	struct ident_state ident;
	const char *host, *port;
	uint8_t buf[65536];
	size_t nread, size;

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	generate_sig_keypair(iska, iska_prv);
	/* generate_kex_keypair(ika, ika_prv); */
	crypto_from_eddsa_public(ika,      iska);
	crypto_from_eddsa_private(ika_prv, iska_prv);

	fd = setclientup(host, port);

	mesg_hshake_cprepare(&state, isks, iks, iska, iska_prv, ika, ika_prv);
	mesg_hshake_chello(&state, buf);
	safe_write(fd, buf, MESG_HELLO_SIZE);
	crypto_wipe(buf, MESG_HELLO_SIZE);

	nread = safe_read(fd, buf, MESG_REPLY_SIZE + 1);
	if (nread != MESG_REPLY_SIZE) {
		fprintf(stderr, "Received invalid reply from server.\n");
		crypto_wipe(buf, MESG_REPLY_SIZE);
		return -1;
	}

	if (mesg_hshake_cfinish(&state, buf)) {
		fprintf(stderr, "Reply message cannot be decrypted.\n");
		crypto_wipe(buf, MESG_REPLY_SIZE);
		return -1;
	}

	crypto_wipe(buf, MESG_REPLY_SIZE);

	size = ident_lookup_msg_init(&ident, MESG_TEXT(buf), "bob");
	mesg_lock(&state, buf, size);
	safe_write(fd, buf, MESG_BUF_SIZE(size));
	crypto_wipe(buf, MESG_BUF_SIZE(size));
	fprintf(stderr, "sent %lu-byte (%lu-byte) lookup message\n",
		size, MESG_BUF_SIZE(size));

	nread = safe_read(fd, buf, 65536);
	if (nread < MESG_BUF_SIZE(0)) {
		fprintf(stderr, "Received a message that is too small.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf", buf, nread);
	if (mesg_unlock(&state, buf, nread)) {
		fprintf(stderr, "Message cannot be decrypted.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf (decrypted)", buf, nread);
	displaykey("text", MESG_TEXT(buf), MESG_TEXT_SIZE(nread));

	{
		struct ident_lookup_reply_msg *msg = (struct ident_lookup_reply_msg *)MESG_TEXT(buf);
		if (MESG_TEXT_SIZE(nread) != sizeof *msg) {
			fprintf(stderr, "Identity lookup reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg);
			crypto_wipe(buf, nread);
			return -1;
		}
		if (msg->msgtype != IDENT_LOOKUP_REP) {
			fprintf(stderr, "Identity lookup reply message has invalid msgtype (%d).\n",
				msg->msgtype);
			crypto_wipe(buf, nread);
			return -1;
		}

		memcpy(iskb, msg->isk, 32);
	}

	size = ident_keyreq_msg_init(&ident, MESG_TEXT(buf), iskb);
	mesg_lock(&state, buf, size);
	safe_write(fd, buf, MESG_BUF_SIZE(size));
	crypto_wipe(buf, MESG_BUF_SIZE(size));
	fprintf(stderr, "sent %lu-byte (%lu-byte) keyreq message\n",
		size, MESG_BUF_SIZE(size));

	nread = safe_read(fd, buf, 65536);
	if (nread < MESG_BUF_SIZE(0)) {
		fprintf(stderr, "Received a message that is too small.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf", buf, nread);
	if (mesg_unlock(&state, buf, nread)) {
		fprintf(stderr, "Message cannot be decrypted.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf (decrypted)", buf, nread);
	displaykey("text", MESG_TEXT(buf), MESG_TEXT_SIZE(nread));

	{
		struct ident_keyreq_reply_msg *msg = (struct ident_keyreq_reply_msg *)MESG_TEXT(buf);
		if (MESG_TEXT_SIZE(nread) != sizeof *msg) {
			fprintf(stderr, "Key bundle request reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg);
			crypto_wipe(buf, nread);
			return -1;
		}
		if (msg->msgtype != IDENT_KEYREQ_REP) {
			fprintf(stderr, "Key bundle request reply message has invalid msgtype (%d).\n",
				msg->msgtype);
			crypto_wipe(buf, nread);
			return -1;
		}

		/* displaykey_short("ik", msg->ik, 32); */

		/* memcpy(ikb,      msg->ik,      32); */
		crypto_from_eddsa_public(ikb, iskb);
		/* memcpy(ikb_sig,  msg->ik_sig,  64); */
		memcpy(spkb,     msg->spk,     32);
		memcpy(spkb_sig, msg->spk_sig, 64);
		memcpy(opkb,     msg->opk,     32);

		displaykey_short("ikb",  ikb,  32);
		displaykey_short("spkb", spkb, 32);
		displaykey_short("opkb", opkb, 32);
		/* displaykey("ikb_sig",  ikb_sig,  64); */
		displaykey("spkb_sig", spkb_sig, 64);
	}

	crypto_wipe(buf, 65536);
	displaykey_short("ika", ika, 32);
	if (mesg_hshake_aprepare(&p2pstate, ika, ika_prv,
		iskb, ikb, /*ikb_sig,*/ spkb, spkb_sig, opkb)) {
		fprintf(stderr, "Error preparing handshake.\n");
		return -1;
	}

	{
		struct ident_forward_msg *msg = (void *)MESG_TEXT(buf);
		msg->msgtype = IDENT_FORWARD_MSG;
		memcpy(msg->isk, iskb, 32);
		msg->message_count = 1;
		store16_le(msg->messages, MESG_P2PHELLO_SIZE(24));
		mesg_hshake_ahello(&p2pstate, msg->messages + 2, 24);
		mesg_lock(&state, buf, IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24)));
		displaykey("buf", buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24))));
		safe_write(fd, buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24))));
	}

	{
		struct ident_forward_msg *msg = (void *)MESG_TEXT(buf);
		msg->msgtype = IDENT_FORWARD_MSG;
		memcpy(msg->isk, iskb, 32);
		msg->message_count = 1;
		store16_le(msg->messages, MESG_P2PHELLO_SIZE(24));
		mesg_hshake_ahello(&p2pstate, msg->messages + 2, 24);
		mesg_lock(&state, buf, IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24)));
		displaykey("buf", buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24))));
		safe_write(fd, buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24))));
	}

	/* memset(MESG_OHELLO_TEXT(MESG_TEXT(buf)), 0x77, 24); */
	/* mesg_hshake_ahello(&p2pstate, MESG_TEXT(buf), 24); */
	/* mesg_lock(&state, buf, MESG_P2PHELLO_SIZE(24)); */
	/* safe_write(fd, buf, MESG_BUF_SIZE(MESG_P2PHELLO_SIZE(24))); */

	/* memset(MESG_TEXT(buf) + MESG_P2PHELLO_SIZE(0), 0x77, 24); */
	/* mesg_hshake_ahello(&p2pstate, MESG_TEXT(buf), 24); */
	/* safe_write(fd, buf, MESG_BUF_SIZE(MESG_P2PHELLO_SIZE(24))); */

	/* memset(MESG_TEXT(buf), 0x77, 24); */
	/* mesg_lock(&state, buf, 24); */

	/* safe_write(fd, buf, MESG_BUF_SIZE(24)); */
	/* crypto_wipe(buf, MESG_BUF_SIZE(24)); */
	/* fprintf(stderr, "sent 24-byte message\n"); */

	nread = safe_read(fd, buf, 65536);
	while ((size_t)nread >= MESG_BUF_SIZE(1)) {
		if (mesg_unlock(&state, buf, nread)) {
			break;
		}

		/* if ((size_t)nread > MESG_BUF_SIZE(1)) { */
		/* 	mesg_lock(&state, buf, MESG_TEXT_SIZE(nread) - 1); */
		/* 	safe_write(fd, buf, nread - 1); */
		/* 	fprintf(stderr, "sent %lu-byte (%lu-byte) message\n", MESG_TEXT_SIZE(nread) - 1, nread - 1); */
		/* } */

		crypto_wipe(buf, 65536);

		nread = safe_read(fd, buf, 65536);
	}

	exit(EXIT_SUCCESS);
fail:
	crypto_wipe(buf, 65536);
	exit(EXIT_FAILURE);
}

static
int
handle_replies(int fd, uint8_t buf[65536], struct mesg_state *state, int minreplies)
{
	size_t nread;

	while ((nread = safe_read_nonblock(fd, buf, 65536)) || minreplies) {
		uint8_t *text = MESG_TEXT(buf);
		size_t size = MESG_TEXT_SIZE(nread);

		if (nread == 0)
			continue;

		if (nread < MESG_BUF_SIZE(0)) {
			fprintf(stderr, "Received a message that is too small.\n");
			goto fail;
		}
		if (mesg_unlock(state, buf, nread)) {
			fprintf(stderr, "Message cannot be decrypted.\n");
			goto fail;
		}
		if (size >= 1) {
			minreplies--;
			switch (text[0]) {
			case IDENT_OPKSSUB_ACK: {
				struct ident_opkssub_ack_msg *msg = (void *)text;
				if (size < sizeof *msg) {
					fprintf(stderr, "OPKs submission ack message is the wrong size.\n");
					goto fail;
				}
				fprintf(stderr, "OPKs submission ack\n");
				fprintf(stderr, "msn:\t%u\n", load32_le(msg->msn));
				fprintf(stderr, "result:\t%d\n", msg->result);
				if (msg->result)
					goto fail;
				break;
			}
			case IDENT_SPKSUB_ACK: {
				struct ident_spksub_ack_msg *msg = (void *)text;
				if (size < sizeof *msg) {
					fprintf(stderr, "SPK submission ack message is the wrong size.\n");
					goto fail;
				}
				fprintf(stderr, "SPK submission ack\n");
				fprintf(stderr, "msn:\t%u\n", load32_le(msg->msn));
				fprintf(stderr, "result:\t%d\n", msg->result);
				if (msg->result)
					goto fail;
				break;
			}
			case IDENT_REGISTER_ACK: {
				struct ident_register_ack_msg *msg = (void *)text;
				if (size < sizeof *msg) {
					fprintf(stderr, "Registration ack message is the wrong size.\n");
					goto fail;
				}
				fprintf(stderr, "Registration submission ack\n");
				fprintf(stderr, "msn:\t%u\n", load32_le(msg->msn));
				fprintf(stderr, "result:\t%d\n", msg->result);
				if (msg->result)
					goto fail;
				break;
			}
			default:
				fprintf(stderr, "Unrecognised message type %d\n", text[0]);
				displaykey("buf (decrypted)", buf, nread);
				displaykey("text", text, size);
				return -1;
			}
		}
	}

	return 0;
fail:
	crypto_wipe(buf, 65536);
	return -1;
}

static
int
bob(int argc, char **argv)
{
	int fd;
	/* uint8_t iskb[32], iskb_prv[32]; */
	/* uint8_t ikb[32], ikb_prv[32]; */
	struct mesg_state state;
	struct mesg_state p2pstate;
	struct ident_state ident;
	const char *host, *port;
	int do_fetch;
	uint8_t buf[65536];
	size_t nread, size;
	int opkcount;
	uint8_t namelen;

	if (argc < 2 || argc > 5)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];
	do_fetch = argc == 5;

	/* generate_sig_keypair(ident.isk, ident.isk_prv); */
	memcpy(ident.isk,     iskb,     32);
	memcpy(ident.isk_prv, iskb_prv, 32);
	/* generate_kex_keypair(ident.ik, ident.ik_prv); */
	crypto_from_eddsa_public(ident.ik,      ident.isk);
	crypto_from_eddsa_private(ident.ik_prv, ident.isk_prv);

	fd = setclientup(host, port);

	mesg_hshake_cprepare(&state, isks, iks, ident.isk, ident.isk_prv, ident.ik, ident.ik_prv);
	mesg_hshake_chello(&state, buf);
	safe_write(fd, buf, MESG_HELLO_SIZE);
	crypto_wipe(buf, MESG_HELLO_SIZE);

	nread = safe_read(fd, buf, MESG_REPLY_SIZE + 1);
	if (nread != MESG_REPLY_SIZE) {
		fprintf(stderr, "Received invalid reply from server.\n");
		goto fail;
	}

	if (mesg_hshake_cfinish(&state, buf)) {
		fprintf(stderr, "Reply message cannot be decrypted.\n");
		goto fail;
	}

	crypto_wipe(buf, MESG_REPLY_SIZE);

	if (!do_fetch) {
		size = ident_register_msg_init(&ident, MESG_TEXT(buf), "bob");
		mesg_lock(&state, buf, size);
		safe_write(fd, buf, MESG_BUF_SIZE(size));
		crypto_wipe(buf, MESG_BUF_SIZE(size));
		fprintf(stderr, "sent %lu-byte (%lu-byte) message\n",
			size, MESG_BUF_SIZE(size));

		if (handle_replies(fd, buf, &state, 1))
			goto fail;

		size = ident_spksub_msg_init(&ident, MESG_TEXT(buf));
		mesg_lock(&state, buf, size);
		safe_write(fd, buf, MESG_BUF_SIZE(size));
		crypto_wipe(buf, MESG_BUF_SIZE(size));
		fprintf(stderr, "sent %lu-byte (%lu-byte) message\n",
			size, MESG_BUF_SIZE(size));

		if (handle_replies(fd, buf, &state, 1))
			goto fail;

		size = ident_opkssub_msg_init(&ident, MESG_TEXT(buf));
		mesg_lock(&state, buf, size);
		safe_write(fd, buf, MESG_BUF_SIZE(size));
		crypto_wipe(buf, MESG_BUF_SIZE(size));
		fprintf(stderr, "sent %lu-byte (%lu-byte) message\n",
			size, MESG_BUF_SIZE(size));

		if (handle_replies(fd, buf, &state, 1))
			goto fail;
	}

	/* if (handle_replies(fd, buf, &state, 1)) */
	/* 	goto fail; */

	while (1) {
		struct ident_fetch_reply_msg *msg = (struct ident_fetch_reply_msg *)MESG_TEXT(buf);
		uint16_t msgsize;

		*MESG_TEXT(buf) = IDENT_FETCH_MSG;
		mesg_lock(&state, buf, 1LU);
		safe_write(fd, buf, MESG_BUF_SIZE(1LU));
		crypto_wipe(buf, MESG_BUF_SIZE(1LU));
		fprintf(stderr, "sent %lu-byte (%lu-byte) message\n",
			1LU, MESG_BUF_SIZE(1LU));

		nread = safe_read(fd, buf, 65536);
		if (nread < MESG_BUF_SIZE(0)) {
			fprintf(stderr, "Received a message that is too small.\n");
			goto fail;
		}
		if (mesg_unlock(&state, buf, nread)) {
			fprintf(stderr, "Message cannot be decrypted.\n");
			goto fail;
		}
		if (MESG_TEXT_SIZE(nread) < sizeof *msg) {
			fprintf(stderr, "Message fetch reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg);
			goto fail;
		}
		if (msg->msgtype != IDENT_FETCH_REP) {
			fprintf(stderr, "Message fetch reply message has invalid msgtype (%d).\n",
				msg->msgtype);
			goto fail;
		}
		if (msg->message_count > 1) {
			fprintf(stderr, "Message fetch replies with more than one message not yet supported (%d).\n",
				msg->message_count);
			goto fail;
		}
		if (msg->message_count == 0) {
			fprintf(stderr, "No messages fetched.\n");
			goto fail;
		}
		if (MESG_TEXT_SIZE(nread) < sizeof *msg + 34) {
			fprintf(stderr, "Message fetch reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg + 34);
			goto fail;
		}
		msgsize = load16_le(msg->messages);
		if (MESG_TEXT_SIZE(nread) < sizeof *msg + 34 + msgsize) {
			fprintf(stderr, "Message fetch reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg + 34 + msgsize);
			goto fail;
		}
		displaykey("sender", msg->messages + 2, 32);
		displaykey("message", msg->messages + 34, msgsize);

		{
			struct hshake_ohello_msg *hmsg = (struct hshake_ohello_msg *)(msg->messages + 34);
			uint8_t ika[32], hk[32];

			crypto_from_eddsa_public(ika, msg->messages + 2);
			crypto_key_exchange(hk, ident.ik_prv, ika);

			displaykey_short("ika", ika, 32);
			displaykey_short("hk", hk, 32);

			displaykey_short("mac", hmsg->mac, 16);
			displaykey_short("nonce", hmsg->nonce, 24);
			displaykey("message (encrypted)", &hmsg->msgtype, msgsize - 40);

			if (crypto_unlock(
					&hmsg->msgtype,
					hk,
					hmsg->nonce,
					hmsg->mac,
					&hmsg->msgtype,
					sizeof(struct hshake_ohello_msg) - offsetof(struct hshake_ohello_msg, msgtype))) {
				fprintf(stderr, "Initial message header cannot be decrypted.\n");
				goto fail;
			}

			displaykey("message (decrypted)", &hmsg->msgtype, msgsize - 40);
			displaykey("eka", hmsg->eka, 32);
		}

		crypto_wipe(buf, nread);
	}


	/* mesg_hshake_aprepare(&p2pstate, ika, ika_prv, */
	/* 	ident.isk, ident.ik, ikb_sig, spkb, spkb_sig, opkb); */
	/* memset(MESG_TEXT(buf), 0x77, 24); */
	/* mesg_lock(&state, buf, 24); */

	/* safe_write(fd, buf, MESG_BUF_SIZE(24)); */
	/* crypto_wipe(buf, MESG_BUF_SIZE(24)); */
	/* fprintf(stderr, "sent 24-byte message\n"); */

	/* nread = safe_read(fd, buf, 65536); */
	/* while ((size_t)nread >= MESG_BUF_SIZE(1)) { */
	/* 	if (mesg_unlock(&state, buf, nread)) { */
	/* 		break; */
	/* 	} */

	/* 	if ((size_t)nread > MESG_BUF_SIZE(1)) { */
	/* 		mesg_lock(&state, buf, MESG_TEXT_SIZE(nread) - 1); */
	/* 		safe_write(fd, buf, nread - 1); */
	/* 		fprintf(stderr, "sent %lu-byte (%lu-byte) message\n", MESG_TEXT_SIZE(nread) - 1, nread - 1); */
	/* 	} */

	/* 	crypto_wipe(buf, 65536); */

	/* 	nread = safe_read(fd, buf, 65536); */
	/* } */

	exit(EXIT_SUCCESS);
fail:
	crypto_wipe(buf, 65536);
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

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	generate_sig_keypair(iskc, iskc_prv);
	/* generate_kex_keypair(ikc, ikc_prv); */
	crypto_from_eddsa_public(ikc,      iskc);
	crypto_from_eddsa_private(ikc_prv, iskc_prv);

	fd = setclientup(host, port);

	{
		uint8_t buf[65536];
		size_t nread;

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

		while (nread > MESG_BUF_SIZE(1)) {
			if (mesg_unlock(&state, buf, nread)) {
				break;
			}

			if (nread > MESG_BUF_SIZE(1)) {
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
		fprintf(stderr, "Error while reading from socket (%d).\n", errno);
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

static
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

static uint8_t zero_key[32] = {0};

struct key {
	uint8_t data[32];
};
struct stored_message {
	uint8_t isk[32];
	uint16_t size;
	uint8_t *data;
};

struct userinfo {
	uint8_t ik[32];
	/* uint8_t ik_sig[64]; */
	uint8_t spk[32];
	uint8_t spk_sig[64];
	struct key *opks;
	struct stored_message *letterbox;
};

struct userkv {
	struct key key;
	struct userinfo value;
};

struct usernamev {
	char *key;
	struct key value;
};

static
void
print_nametable(struct usernamev *table)
{
	ptrdiff_t len, i;
	struct usernamev *el;

	len = stbds_shlen(table);
	fprintf(stderr, "table length = %ld\n", len);

	for (i = 0; i < len; i++) {
		fprintf(stderr, "el = %p\n", (void *)(el = &table[i]));
		fprintf(stderr, "key = %s\n", el->key);
		displaykey_short("isk", el->value.data, 32);
	}
}

static
void
print_table(struct userkv *table)
{
	ptrdiff_t len, i;
	struct userkv *el;

	len = stbds_hmlen(table);
	fprintf(stderr, "table length = %ld\n", len);

	for (i = 0; i < len; i++) {
		ptrdiff_t arrlen, j;
		fprintf(stderr, "el = %p\n", (void *)(el = &table[i]));
		displaykey_short("isk", el->key.data, 32);
		displaykey_short("ik", el->value.ik, 32);
		/* displaykey_short("ik_sig", el->value.ik_sig, 64); */
		displaykey_short("spk", el->value.spk, 32);
		displaykey_short("spksig", el->value.spk_sig, 64);

		arrlen = stbds_arrlen(el->value.opks);
		for (j = 0; j < arrlen; j++) {
			struct key *opk = &el->value.opks[j];
			displaykey_short("opk", opk->data, 32);
		}

		arrlen = stbds_arrlen(el->value.letterbox);
		for (j = 0; j < arrlen; j++) {
			displaykey_short("sender", el->value.letterbox[j].isk, 32);
			displaykey("message", el->value.letterbox[j].data, el->value.letterbox[j].size);
		}
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
	struct userkv *table = NULL;
	struct usernamev *namestable = NULL;

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	if (peertable_init(&peertable)) {
		fprintf(stderr, "Couldn't initialise peer table.\n");
		exit(EXIT_FAILURE);
	}

	memset(buf, 0, 65536);
	stbds_sh_new_arena(namestable);

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

		if (!getnameinfo(sstosa(&pi.addr), pi.addr_len,
				host, NI_MAXHOST,
				service, NI_MAXSERV,
				NI_NUMERICHOST|NI_NUMERICSERV)) {
			fprintf(stderr, "Peer %s on port %s\n",
				host, service);
		} else {
			fprintf(stderr, "Peer on unknown host and port\n");
		}

		fprintf(stderr, "Received %zu bytes. ", nread);

		peer = peer_getbyaddr(&peertable, sstosa(&pi.addr), pi.addr_len);
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
					sstosa(&peer->addr),
					peer->addr_len);
				crypto_wipe(buf, MESG_REPLY_SIZE);

				peer->status = PEER_ACTIVE;
				fprintf(stderr, "Peer status: %d\n", peer->status);
				continue;
			}

			fprintf(stderr, "Whoops it wasn't a HELLO... at least not a valid one\n");
			/* Fall through: check if it's a real message */
		}

		if (nread > MESG_BUF_SIZE(0)) {
			struct mesghdr *hdr = MESG_HDR(buf);
			uint8_t *text = MESG_TEXT(buf);
			size_t size = MESG_TEXT_SIZE(nread);

			displaykey("buf", buf, nread);

			if (mesg_unlock(&peer->state, buf, nread)) {
				fprintf(stderr, "Couldn't decrypt message with size=%lu (text_size=%lu)\n",
					nread, MESG_TEXT_SIZE(nread));
				continue;
			}

			displaykey("buf (decrypted)", buf, nread);
			displaykey("text", text, size);

			if (size >= 1) {
				int msgtype = text[0];
				fprintf(stderr, "msg type = %d\n", msgtype);
				switch (msgtype) {
				case IDENT_REGISTER_MSG: {
					struct ident_register_msg *msg = (struct ident_register_msg *)text;
					struct key isk;
					struct userinfo ui = {0};
					uint8_t result = 1;
					if (size < IDENT_REGISTER_MSG_BASE_SIZE) {
						fprintf(stderr, "Registration message (%lu) is too short (%lu).\n",
							size, IDENT_REGISTER_MSG_BASE_SIZE);
						goto register_fail;
					}
					fprintf(stderr, "Username length: %d\n", msg->username_len);
					if (size != IDENT_REGISTER_MSG_SIZE(msg->username_len)) {
						fprintf(stderr, "Registration message (%lu) is the wrong size (%lu).\n",
							size, IDENT_REGISTER_MSG_SIZE(msg->username_len));
						goto register_fail;
					}
					memcpy(isk.data, peer->state.u.rad.iskc, 32);
					/* if (check_key(isk.data, "AIBI", msg->ik, msg->ik_sig)) { */
					/* 	fprintf(stderr, "Failed signature\n"); */
					/* 	goto register_fail; */
					/* } */
					if (stbds_hmgetp_null(table, isk) != NULL) {
						fprintf(stderr, "Cannot register an already-registered identity key.\n");
						goto register_fail;
					}
					fprintf(stderr, "msg->username: %s\n", msg->username);
					fprintf(stderr, "%s in table?: %d\n", msg->username, stbds_shgetp_null(namestable, msg->username) != NULL);
					if (stbds_shgetp_null(namestable, msg->username) != NULL) {
						fprintf(stderr, "Cannot register an already-registered username.\n");
						goto register_fail;
					}
					result = 0;
					/* memcpy(ui.ik, msg->ik, 32); */
					/* memcpy(ui.ik_sig, msg->ik_sig, 64); */
					crypto_from_eddsa_public(ui.ik, isk.data);
					stbds_hmput(table, isk, ui);
					fprintf(stderr, "msg->username: %s\n", msg->username);
					stbds_shput(namestable, msg->username, isk);
				register_fail:
					{
						size_t repsize = ident_register_ack_init(MESG_TEXT(buf), hdr->msn, result);
						mesg_lock(&peer->state, buf, repsize);
						safe_sendto(fd, buf, MESG_BUF_SIZE(repsize),
							sstosa(&pi.addr), pi.addr_len);
						crypto_wipe(buf, MESG_BUF_SIZE(repsize));
						fprintf(stderr, "sent %lu-byte (%lu-byte) registration ack\n",
							repsize, MESG_BUF_SIZE(repsize));
					}
					print_table(table);
					print_nametable(namestable);
					break;
				}
				case IDENT_SPKSUB_MSG: {
					struct ident_spksub_msg *msg = (struct ident_spksub_msg *)text;
					struct key isk;
					struct userkv *kv;
					uint8_t result = 1;
					if (size != IDENT_SPKSUB_MSG_SIZE) {
						fprintf(stderr, "Signed prekey submission message (%lu) is the wrong size (%lu).\n",
							size, IDENT_SPKSUB_MSG_SIZE);
						goto spksub_fail;
					}

					memcpy(isk.data, peer->state.u.rad.iskc, 32);
					if ((kv = stbds_hmgetp_null(table, isk)) == NULL) {
						fprintf(stderr, "Can only submit a signed prekey for a registered identity.\n");
						goto spksub_fail;
					}

					if (check_key(isk.data, "AIBS", msg->spk, msg->spk_sig)) {
						fprintf(stderr, "Failed signature\n");
						goto spksub_fail;
					}
					result = 0;
					memcpy(kv->value.spk, msg->spk, 32);
					memcpy(kv->value.spk_sig, msg->spk_sig, 64);
				spksub_fail:
					{
						size_t repsize = ident_spksub_ack_init(MESG_TEXT(buf), hdr->msn, result);
						mesg_lock(&peer->state, buf, repsize);
						safe_sendto(fd, buf, MESG_BUF_SIZE(repsize),
							sstosa(&pi.addr), pi.addr_len);
						crypto_wipe(buf, MESG_BUF_SIZE(repsize));
						fprintf(stderr, "sent %lu-byte (%lu-byte) spk submission ack\n",
							repsize, MESG_BUF_SIZE(repsize));
					}
					print_table(table);
					print_nametable(namestable);
					break;
				}
				case IDENT_OPKSSUB_MSG: {
					struct ident_opkssub_msg *msg = (struct ident_opkssub_msg *)text;
					struct key isk;
					struct userkv *kv;
					int i;
					uint16_t opkcount;
					uint8_t result = 1;

					if (size < IDENT_OPKSSUB_MSG_BASE_SIZE) {
						fprintf(stderr, "One-time prekey submission message (%lu) is too short (%lu).\n",
							size, IDENT_OPKSSUB_MSG_BASE_SIZE);
						goto opkssub_fail;
					}

					opkcount = load16_le(msg->opk_count);
					fprintf(stderr, "OPK count: %d\n", opkcount);
					if (size != IDENT_OPKSSUB_MSG_SIZE(opkcount)) {
						fprintf(stderr, "One-time prekey submission message (%lu) is the wrong size (%lu).\n",
							size, IDENT_OPKSSUB_MSG_SIZE(opkcount));
						goto opkssub_fail;
					}

					memcpy(isk.data, peer->state.u.rad.iskc, 32);
					if ((kv = stbds_hmgetp_null(table, isk)) == NULL) {
						fprintf(stderr, "Can only submit one-time prekeys for a registered identity.\n");
						goto opkssub_fail;
					}

					result = 0;
					
					stbds_arrsetcap(kv->value.opks, opkcount);
					for (i = 0; i < opkcount; i++) {
						struct key opk;
						memcpy(opk.data, msg->opk[i], 32);
						stbds_arrput(kv->value.opks, opk);
						displaykey_short("opk", kv->value.opks[stbds_arrlen(kv->value.opks) - 1].data, 32);
					}

				opkssub_fail:
					{
						size_t repsize = ident_opkssub_ack_init(MESG_TEXT(buf), hdr->msn, result);
						mesg_lock(&peer->state, buf, repsize);
						safe_sendto(fd, buf, MESG_BUF_SIZE(repsize),
							sstosa(&pi.addr), pi.addr_len);
						crypto_wipe(buf, MESG_BUF_SIZE(repsize));
						fprintf(stderr, "sent %lu-byte (%lu-byte) opk submission ack\n",
							repsize, MESG_BUF_SIZE(repsize));
					}

					print_table(table);
					print_nametable(namestable);
					break;
				}
				case IDENT_LOOKUP_MSG: {
					struct ident_lookup_msg *msg = (struct ident_lookup_msg *)text;
					struct key k = {0};
					uint8_t namelen;
					if (size < IDENT_LOOKUP_MSG_BASE_SIZE) {
						fprintf(stderr, "Username lookup message (%lu) is too small (%lu).\n",
							size, IDENT_LOOKUP_MSG_BASE_SIZE);
						goto lookup_fail;
					}
					namelen = msg->username_len;
					if (size != IDENT_LOOKUP_MSG_SIZE(namelen)) {
						fprintf(stderr, "Username lookup message (%lu) is the wrong size (%lu).\n",
							size, IDENT_LOOKUP_MSG_SIZE(namelen));
						goto lookup_fail;
					}
					if (msg->username[namelen] != '\0') {
						fprintf(stderr, "Username lookup message is invalid.\n");
						goto lookup_fail;
					}

					k = stbds_shget(namestable, msg->username);

				lookup_fail:
					{
						size_t repsize = ident_lookup_rep_init(MESG_TEXT(buf), hdr->msn, k.data);
						mesg_lock(&peer->state, buf, repsize);
						safe_sendto(fd, buf, MESG_BUF_SIZE(repsize),
							sstosa(&pi.addr), pi.addr_len);
						crypto_wipe(buf, MESG_BUF_SIZE(repsize));
						fprintf(stderr, "sent %lu-byte (%lu-byte) lookup reply message\n",
							repsize, MESG_BUF_SIZE(repsize));
					}

					print_table(table);
					print_nametable(namestable);
					break;
				}
				case IDENT_KEYREQ_MSG: {
					struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)text;
					struct key isk;
					struct userkv *kv;
					struct userinfo blank = {0}, *value = &blank;
					struct key opk = {0};

					if (size != IDENT_KEYREQ_MSG_SIZE) {
						fprintf(stderr, "Key bundle request message (%lu) is the wrong size (%lu).\n",
							size, IDENT_KEYREQ_MSG_SIZE);
						goto keyreq_fail;
					}

					memcpy(isk.data, msg->isk, 32);
					if ((kv = stbds_hmgetp_null(table, isk)) == NULL) {
						fprintf(stderr, "Can only request a key bundle for a registered identity.\n");
						goto keyreq_fail;
					}

					value = &kv->value;
					displaykey_short("ik", kv->value.ik, 32);

					if (stbds_arrlen(kv->value.opks) > 0) {
						opk = stbds_arrpop(kv->value.opks);
					} else {
						crypto_wipe(opk.data, 32);
					}

				keyreq_fail:
					{
						size_t repsize = ident_keyreq_rep_init(MESG_TEXT(buf), hdr->msn,
							/* value->ik, value->ik_sig, */
							value->spk, value->spk_sig, opk.data);
						mesg_lock(&peer->state, buf, repsize);
						safe_sendto(fd, buf, MESG_BUF_SIZE(repsize),
							sstosa(&pi.addr), pi.addr_len);
						crypto_wipe(buf, MESG_BUF_SIZE(repsize));
						fprintf(stderr, "sent %lu-byte (%lu-byte) keyreq reply message\n",
							repsize, MESG_BUF_SIZE(repsize));
					}

					print_table(table);
					print_nametable(namestable);
					break;
				}
				case IDENT_FETCH_MSG: {
					struct ident_fetch_msg *msg = (struct ident_fetch_msg *)text;
					int msgcount = 0;
					ptrdiff_t arrlen;
					uint16_t message_size;
					uint16_t slack;
					struct key isk;
					struct userkv *kv;
					struct stored_message smsg;

					if (size < IDENT_FETCH_MSG_BASE_SIZE) {
						fprintf(stderr, "Message-fetching message (%lu) is too small (%lu).\n",
							size, IDENT_FETCH_MSG_BASE_SIZE);
						goto fetch_fail;
					}

					memcpy(isk.data, peer->state.u.rad.iskc, 32);
					if ((kv = stbds_hmgetp_null(table, isk)) == NULL) {
						fprintf(stderr, "Only registered identities may fetch messages.\n");
						goto fetch_fail;
					}
						
					/* TODO: set to maximum value that makes total packet size <= 64k */
					/* slack = 32768; */

					/* for now, fetch only 1 message at a time */
					arrlen = stbds_arrlen(kv->value.letterbox);
					if (arrlen == 0) {
						fprintf(stderr, "No messages to fetch.\n");
						goto fetch_fail;
					}
					smsg = stbds_arrpop(kv->value.letterbox);
					msgcount = 1;

				fetch_fail:
					{
						size_t repsize = ident_fetch_rep_init(MESG_TEXT(buf), hdr->msn, msgcount);
						struct ident_fetch_reply_msg *msg = (struct ident_fetch_reply_msg *)MESG_TEXT(buf);

						if (msgcount == 1) {
							store16_le(msg->messages, smsg.size);
							memcpy(msg->messages + 2,      smsg.isk,  32);
							memcpy(msg->messages + 2 + 32, smsg.data, smsg.size);
							repsize += smsg.size + 2 + 32;
						}

						mesg_lock(&peer->state, buf, repsize);
						safe_sendto(fd, buf, MESG_BUF_SIZE(repsize),
							sstosa(&pi.addr), pi.addr_len);
						crypto_wipe(buf, MESG_BUF_SIZE(repsize));
						fprintf(stderr, "sent %lu-byte (%lu-byte) message-fetching ack\n",
							repsize, MESG_BUF_SIZE(repsize));
					}

					print_table(table);
					print_nametable(namestable);
					break;
				}
				case IDENT_FORWARD_MSG: {
					struct ident_forward_msg *msg = (struct ident_forward_msg *)text;
					int result = 1;
					uint8_t msgcount;
					uint16_t message_size;
					struct key isk;
					struct userkv *kv;
					struct stored_message smsg = {0};

					if (size < IDENT_FORWARD_MSG_BASE_SIZE) {
						fprintf(stderr, "Message-forwarding message (%lu) is too small (%lu).\n",
							size, IDENT_FORWARD_MSG_BASE_SIZE);
						goto forward_fail;
					}

					msgcount = msg->message_count;
					fprintf(stderr, "msgcount: %d\n", msgcount);
					if (msgcount != 1) {
						fprintf(stderr, "Message-forwarding messages with more than one message within not yet supported.\n");
						goto forward_fail;
					}
					if (size < IDENT_FORWARD_MSG_BASE_SIZE + 2) {
						fprintf(stderr, "Message-forwarding message (%lu) is too small (%lu).\n",
							size, IDENT_FORWARD_MSG_BASE_SIZE + 2);
						goto forward_fail;
					}

					message_size = load16_le(msg->messages);
					fprintf(stderr, "msgsize: %u\n", message_size);
					if (size != IDENT_FORWARD_MSG_BASE_SIZE + 2 + message_size) {
						fprintf(stderr, "Message-forwarding message (%lu) is the wrong size (%lu).\n",
							size, IDENT_FORWARD_MSG_BASE_SIZE + 2 + message_size);
						goto forward_fail;
					}

					memcpy(isk.data, msg->isk, 32);
					displaykey_short("msgisk", msg->isk, 32);
					if ((kv = stbds_hmgetp_null(table, isk)) == NULL) {
						fprintf(stderr, "Can only forward messages to a registered identity.\n");
						goto forward_fail;
					}

					smsg.data = malloc(message_size);
					if (smsg.data == NULL) {
						fprintf(stderr, "Cannot allocate memory.\n");
						goto forward_fail;
					}
						
					result = 0;

					memcpy(smsg.isk, peer->state.u.rad.iskc, 32);
					memcpy(smsg.data, msg->messages + 2, message_size);
					smsg.size = message_size;
					stbds_arrpush(kv->value.letterbox, smsg);

				forward_fail:
					{
						size_t repsize = ident_forward_ack_init(MESG_TEXT(buf), hdr->msn, result);
						mesg_lock(&peer->state, buf, repsize);
						safe_sendto(fd, buf, MESG_BUF_SIZE(repsize),
							sstosa(&pi.addr), pi.addr_len);
						crypto_wipe(buf, MESG_BUF_SIZE(repsize));
						fprintf(stderr, "sent %lu-byte (%lu-byte) message-forwarding ack\n",
							repsize, MESG_BUF_SIZE(repsize));
					}

					print_table(table);
					print_nametable(namestable);
					break;
				}
				default: fprintf(stderr, "fail\n"); abort();
				}
			}

			continue;

			mesg_lock(&peer->state, buf, MESG_TEXT_SIZE(nread));
			safe_sendto(fd, buf, nread,
				sstosa(&pi.addr), pi.addr_len);
			crypto_wipe(buf, nread);

			continue;
		}

		/* It wasn't a valid message at all. */
		fprintf(stderr, "fail: invalid message\n"); abort();
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
	uint8_t difficulty = 24;

	(void)argv;

	if (argc != 2)
		usage();

	randbytes(challenge, 32);
	randbytes(signing_key_prv, 32);
	crypto_sign_public_key(signing_key, signing_key_prv);

	displaykey_short("challenge", challenge, 32);
	displaykey_short("public key", signing_key, 32);
	displaykey_short("private key", signing_key_prv, 32);

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

	displaykey_short("pub", pub, 32);
	displaykey_short("prv", prv, 32);
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
	uint8_t seed[8];

	progname = argv[0];

	if (argc < 2)
		usage();

	randbytes(seed, 8);
	stbds_rand_seed(load64_le(seed));

	switch (argv[1][0]) {
		case 'k': keygen(argc, argv); break;
		case 'p': proof(argc, argv); break;
		case 'a': alice(argc, argv); break;
		case 'b': bob(argc, argv); break;
		case 'c': client(argc, argv); break;
		case 'd': serve(argc, argv); break;
		default:  usage();
	}

	return 0;
}
