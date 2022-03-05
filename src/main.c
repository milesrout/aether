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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>

#include "monocypher.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

#include "err.h"
#include "hkdf.h"
#include "util.h"
#include "packet.h"
#include "peertable.h"
#include "proof.h"
#include "msg.h"
#include "ident.h"
#include "messaging.h"
#include "io.h"
#include "main.h"
#include "fibre.h"
#include "timer.h"

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

#define STACK_SIZE (128 * 1024)

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

const char *progname;

/* the following functions are "safe" in the sense that instead of returning an
 * error, they abort the program.  They are not safe in the sense that they
 * cannot produce errors or in the sense that they can be used with impunity.
 */

struct stored_message {
	uint8_t isk[32];
	uint16_t size;
	uint8_t *data;
};

struct userinfo {
	uint8_t ik[32];
	uint8_t spk[32];
	uint8_t spk_sig[64];
	struct key *opks;
	struct stored_message *letterbox;
	char *username;
	struct peer *peer;
};

struct userkv {
	struct key key;
	struct userinfo value;
};

struct usernamev {
	char *key;
	struct key value;
};

struct server_ctx {
	struct peertable peertable;
	struct userkv *table;
	struct usernamev *namestable;
};

static
void
print_nametable(struct usernamev *table)
{
	ptrdiff_t len, i;
	struct usernamev *el;

	len = stbds_shlen(table);
	printf("table length = %ld\n", len);

	for (i = 0; i < len; i++) {
		printf("el = %p\n", (void *)(el = &table[i]));
		printf("key = %s\n", el->key);
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
	printf("table length = %ld\n", len);

	for (i = 0; i < len; i++) {
		ptrdiff_t arrlen, j;
		printf("el = %p\n", (void *)(el = &table[i]));
		displaykey_short("isk", el->key.data, 32);
		displaykey_short("ik", el->value.ik, 32);
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
send_packet(int fd, struct peer *peer, uint8_t *buf, size_t size)
{
	packet_lock(&peer->state, buf, size);
	safe_sendto(fd, buf, PACKET_BUF_SIZE(size),
		sstosa(&peer->addr), peer->addr_len);
	crypto_wipe(buf, PACKET_BUF_SIZE(size));
}

static
void
handle_register(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_register_msg *msg = (struct ident_register_msg *)text;
	struct key isk;
	struct userinfo ui = {0};
	struct userkv *kv;
	uint8_t failure = 1;

	if (size < IDENT_REGISTER_MSG_BASE_SIZE)
		errg(fail, "Registration message (%lu) is too short (%lu).",
			size, IDENT_REGISTER_MSG_BASE_SIZE);

	if (size < IDENT_REGISTER_MSG_SIZE(msg->username_len))
		errg(fail, "Registration message (%lu) is the wrong size (%lu).",
			size, IDENT_REGISTER_MSG_SIZE(msg->username_len));

	if (msg->username[msg->username_len] != '\0')
		errg(fail, "Cannot register a username that is not a valid string.");

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) != NULL) {
		if (strcmp(kv->value.username, (const char *)msg->username) == 0) {
			failure = 0;
			goto fail;
		}
		errg(fail, "Cannot register an already-registered identity key.");
	}

	if (stbds_shgetp_null(ctx->namestable, msg->username) != NULL)
		errg(fail, "Cannot register an already-registered username.");

	failure = 0;

	crypto_from_eddsa_public(ui.ik, isk.data);
	stbds_shput(ctx->namestable, msg->username, isk);
	ui.username = ctx->namestable[stbds_shlen(ctx->namestable) - 1].key;
	ui.peer = peer;
	printf("username: %s\n", ui.username);
	stbds_hmput(ctx->table, isk, ui);

fail:
	size = ident_register_ack_init(PACKET_TEXT(buf), failure);
	send_packet(fd, peer, buf, size);
	printf("sent %lu-byte (%lu-byte) register ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
	print_nametable(ctx->namestable);
}

static
void
handle_spksub(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_spksub_msg *msg = (struct ident_spksub_msg *)text;
	struct key isk;
	struct userkv *kv;
	uint8_t failure = 1;

	if (size < IDENT_SPKSUB_MSG_SIZE)
		errg(fail, "Signed prekey submission message (%lu) is the wrong size (%lu).",
			size, IDENT_SPKSUB_MSG_SIZE);

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg(fail, "Can only submit a signed prekey for a registered identity.");

	if (check_key(isk.data, "AIBS", msg->spk, msg->spk_sig))
		errg(fail, "Failed signature");

	failure = 0;
	memcpy(kv->value.spk, msg->spk, 32);
	memcpy(kv->value.spk_sig, msg->spk_sig, 64);

fail:
	size = ident_spksub_ack_init(PACKET_TEXT(buf), failure);
	send_packet(fd, peer, buf, size);
	printf("sent %lu-byte (%lu-byte) spksub ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
}

static
void
handle_opkssub(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_opkssub_msg *msg = (struct ident_opkssub_msg *)text;
	struct key isk;
	struct userkv *kv;
	int i;
	uint16_t opkcount;
	uint8_t failure = 1;

	if (size < IDENT_OPKSSUB_MSG_BASE_SIZE)
		errg(fail, "One-time prekey submission message (%lu) is too short (%lu).",
			size, IDENT_OPKSSUB_MSG_BASE_SIZE);

	opkcount = load16_le(msg->opk_count);
	printf("OPK count: %d\n", opkcount);
	if (size < IDENT_OPKSSUB_MSG_SIZE(opkcount))
		errg(fail, "One-time prekey submission message (%lu) is the wrong size (%lu).",
			size, IDENT_OPKSSUB_MSG_SIZE(opkcount));

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg(fail, "Can only submit one-time prekeys for a registered identity.");

	failure = 0;

	stbds_arrsetcap(kv->value.opks, opkcount);
	for (i = 0; i < opkcount; i++) {
		struct key opk;
		memcpy(opk.data, msg->opk[i], 32);
		stbds_arrput(kv->value.opks, opk);
	}

fail:
	size = ident_opkssub_ack_init(PACKET_TEXT(buf), failure);
	send_packet(fd, peer, buf, size);
	printf("sent %lu-byte (%lu-byte) opkssub ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
}

static
void
handle_lookup(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_lookup_msg *msg = (struct ident_lookup_msg *)text;
	struct key k = {0};
	uint8_t namelen;

	if (size < IDENT_LOOKUP_MSG_BASE_SIZE)
		errg(fail, "Username lookup message (%lu) is too small (%lu).",
			size, IDENT_LOOKUP_MSG_BASE_SIZE);
	namelen = msg->username_len;
	if (size < IDENT_LOOKUP_MSG_SIZE(namelen))
		errg(fail, "Username lookup message (%lu) is the wrong size (%lu).",
			size, IDENT_LOOKUP_MSG_SIZE(namelen));
	if (msg->username[namelen] != '\0')
		errg(fail, "Username lookup message is invalid.");

	k = stbds_shget(ctx->namestable, msg->username);

fail:
	size = ident_lookup_rep_init(PACKET_TEXT(buf), k.data);
	send_packet(fd, peer, buf, size);
	printf("sent %lu-byte (%lu-byte) lookup ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_nametable(ctx->namestable);
}

static
void
handle_reverse_lookup(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_reverse_lookup_msg *msg = (struct ident_reverse_lookup_msg *)text;
	struct key isk;
	struct userkv *kv;
	char blankusername[] = "";
	struct userinfo blank = {.username = blankusername}, *value = &blank;

	if (size < IDENT_REVERSE_LOOKUP_MSG_SIZE)
		errg(fail, "Username reverse-lookup message (%lu) is too small (%lu).",
			size, IDENT_REVERSE_LOOKUP_MSG_SIZE);

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg(fail, "Can only look up a username of a registered identity.");

	value = &kv->value;

fail:
	size = ident_reverse_lookup_rep_init(PACKET_TEXT(buf),
		value->username);
	send_packet(fd, peer, buf, size);
	printf("sent %lu-byte (%lu-byte) reverse lookup ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_nametable(ctx->namestable);
}

static
void
handle_keyreq(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)text;
	struct key isk;
	struct userkv *kv;
	struct userinfo blank = {0}, *value = &blank;
	struct key opk = {0};

	if (size < IDENT_KEYREQ_MSG_SIZE)
		errg(fail, "Key bundle request message (%lu) is the wrong size (%lu).",
			size, IDENT_KEYREQ_MSG_SIZE);

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg(fail, "Can only request a key bundle for a registered identity.");

	value = &kv->value;

	if (stbds_arrlen(value->opks) > 0)
		opk = stbds_arrpop(value->opks);
	else
		crypto_wipe(opk.data, 32);

fail:
	size = ident_keyreq_rep_init(PACKET_TEXT(buf),
		value->spk, value->spk_sig, opk.data);
	send_packet(fd, peer, buf, size);
	printf("sent %lu-byte (%lu-byte) key request ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
}


static
void
handle_fetch(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	int msgcount = 0;
	ptrdiff_t arrlen;
	/* uint16_t slack; */
	struct key isk;
	struct userkv *kv;
	struct stored_message smsg;
	size_t totalmsglength;

	if (size < MSG_FETCH_MSG_SIZE)
		errg(fail, "Message-fetching message (%lu) is too small (%lu).",
			size, MSG_FETCH_MSG_SIZE);

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg(fail, "Only registered identities may fetch messages.");

	/* TODO: set to maximum value that makes total packet size <= 64k */
	/* slack = 32768; */

	/* for now, fetch only 1 message at a time */
	arrlen = stbds_arrlen(kv->value.letterbox);
	if (arrlen == 0)
		goto fail;

	smsg = kv->value.letterbox[0];
	stbds_arrdel(kv->value.letterbox, 0);
	msgcount = 1;

fail:
	totalmsglength = msgcount == 0 ? 0 : smsg.size + 34;
	size = msg_fetch_rep_init(text, msgcount, totalmsglength);

	{
		struct msg_fetch_reply_msg *msg = (struct msg_fetch_reply_msg *)text;

		if (msgcount == 1) {
			struct msg_fetch_content_msg *innermsg = (struct msg_fetch_content_msg *)msg->messages;
			store16_le(innermsg->len, smsg.size);
			memcpy(innermsg->isk,  smsg.isk,  32);
			memcpy(innermsg->text, smsg.data, smsg.size);
		}
	}

	send_packet(fd, peer, buf, size);
	printf("sent %lu-byte (%lu-byte) message fetch reply message\n",
		size, PACKET_BUF_SIZE(size));
}

static
void
handle_forward(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct msg_forward_msg *msg = (struct msg_forward_msg *)text;
	struct msg_fetch_reply_msg *repmsg;
	struct msg_fetch_content_msg *innermsg;
	struct userkv *kv;
	struct stored_message smsg;
	struct key isk;
	int result = 1;
	uint16_t message_size;
	size_t repsize, totalmsglength;

	if (size < MSG_FORWARD_MSG_BASE_SIZE)
		errg(fail, "Message-forwarding message (%lu) is too small (%lu).",
			size, MSG_FORWARD_MSG_BASE_SIZE);

	if (msg->message_count != 1)
		errg(fail, "Message-forwarding messages with more than one message within not yet supported.");

	if (size < MSG_FORWARD_MSG_BASE_SIZE + 2)
		errg(fail, "Message-forwarding message (%lu) is too small (%lu).",
			size, MSG_FORWARD_MSG_BASE_SIZE + 2);

	message_size = load16_le(msg->messages);
	if (size < MSG_FORWARD_MSG_SIZE(2 + message_size))
		errg(fail, "Message-forwarding message (%lu) is the wrong size (%lu).",
			size, MSG_FORWARD_MSG_SIZE(2 + message_size));

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg(fail, "Can only forward messages to a registered identity.");

	result = 0;

	if (kv->value.peer == NULL) {
		smsg.data = malloc(message_size);
		if (smsg.data == NULL) {
			result = 1;
			errg(fail, "Cannot allocate memory.");
		}

		memcpy(smsg.isk, peer->state.u.rad.iskc, 32);
		memcpy(smsg.data, msg->messages + 2, message_size);
		smsg.size = message_size;

		crypto_wipe(buf, nread);

		stbds_arrpush(kv->value.letterbox, smsg);
	} else {
		repmsg = (struct msg_fetch_reply_msg *)text;
		innermsg = (struct msg_fetch_content_msg *)repmsg->messages;

		memmove(innermsg->text, msg->messages + 2, message_size);

		totalmsglength = message_size + 34;
		repsize = msg_fetch_rep_init(PACKET_TEXT(buf), 1, totalmsglength);
		repmsg->msg.type = MSG_IMMEDIATE;

		store16_le(innermsg->len, message_size);
		memcpy(innermsg->isk,  peer->state.u.rad.iskc, 32);

		send_packet(fd, kv->value.peer, buf, repsize);
		printf("sent %lu-byte (%lu-byte) immediate forwarding message\n",
			repsize, PACKET_BUF_SIZE(repsize));
	}

fail:
	repsize = msg_forward_ack_init(PACKET_TEXT(buf), result);
	send_packet(fd, peer, buf, repsize);
	printf("sent %lu-byte (%lu-byte) forward ack message\n",
		repsize, PACKET_BUF_SIZE(repsize));
}

static
void
handle_datagram(int fd, struct server_ctx *ctx)
{
	size_t nread;
	uint8_t buf[65536] = {0};
	struct peer *peer;
	struct peer_init pi = {0};

	pi.addr_len = sizeof(pi.addr);
	nread = safe_recvfrom_nonblock(fd, buf, 65536,
		&pi.addr, &pi.addr_len);

	printf("Received %zu bytes. ", nread);

	peer = peer_getbyaddr(&ctx->peertable, sstosa(&pi.addr), pi.addr_len);
	if (peer == NULL) {
		printf("Peer not found. ");
		peer = peer_add(&ctx->peertable, &pi);
		if (peer == NULL)
			errx(EXIT_FAILURE, "Failed to add peer to peertable.");
	} else printf("Peer in table. ");

	if (peer_getnameinfo(peer))
		printf("Peer on unknown host and port. ");
	else
		printf("Peer %s on port %s. ",
			peer->host, peer->service);

	printf("Peer status: %d\n", peer->status);

	/* This is either a HELLO message from a new peer or a message
	 * from a peer that isn't new but has just changed addresses
	 * that just happens to be exactly PACKET_HELLO_SIZE bytes.
	 */
	if (peer->status == PEER_NEW && nread == PACKET_HELLO_SIZE) {
		printf("This appears to be a HELLO message from a new peer.\n");

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

		packet_hshake_dprepare(&peer->state,
			isks, isks_prv, iks, iks_prv);

		if (!packet_hshake_dcheck(&peer->state, buf)) {
			crypto_wipe(buf, PACKET_HELLO_SIZE);

			packet_hshake_dreply(&peer->state, buf);
			safe_sendto(fd, buf, PACKET_REPLY_SIZE,
				sstosa(&peer->addr),
				peer->addr_len);
			crypto_wipe(buf, PACKET_REPLY_SIZE);

			peer->status = PEER_ACTIVE;
			printf("Peer status: %d\n", peer->status);
			return;
		}

		printf("Whoops it wasn't a HELLO... at least not a valid one\n");
		/* Fall through: check if it's a real message */
	}

	/* printf("nread: %lu\n", nread); */

	if (nread <= PACKET_BUF_SIZE(0))
		errx(EXIT_FAILURE, "invalid message (%lu)", nread);

	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);

	if (packet_unlock(&peer->state, buf, nread)) {
		fprintf(stderr, "Couldn't decrypt message with size=%lu (text_size=%lu)\n",
			nread, PACKET_TEXT_SIZE(nread));
		return;
	}

	if (size >= sizeof(struct msg)) {
		struct msg *msg = (struct msg *)text;
		/* printf("msg proto = %d\n", msg->proto); */
		/* printf("msg type = %d\n", msg->type); */
		/* printf("msg len = %d\n", load16_le(msg->len)); */
		switch (msg->proto) {
		case PROTO_IDENT:
			switch (msg->type) {
			case IDENT_REGISTER_MSG:
				handle_register(ctx, peer, fd, buf, nread);
				break;
			case IDENT_SPKSUB_MSG:
				handle_spksub(ctx, peer, fd, buf, nread);
				break;
			case IDENT_OPKSSUB_MSG:
				handle_opkssub(ctx, peer, fd, buf, nread);
				break;
			case IDENT_LOOKUP_MSG:
				handle_lookup(ctx, peer, fd, buf, nread);
				break;
			case IDENT_REVERSE_LOOKUP_MSG:
				handle_reverse_lookup(ctx, peer, fd, buf, nread);
				break;
			case IDENT_KEYREQ_MSG:
				handle_keyreq(ctx, peer, fd, buf, nread);
				break;
			default:
				fprintf(stderr, "fail\n");
				abort();
			}
			break;
		case PROTO_MSG:
			switch (msg->type) {
			case MSG_FETCH_MSG:
				handle_fetch(ctx, peer, fd, buf, nread);
				break;
			case MSG_FORWARD_MSG: 
				handle_forward(ctx, peer, fd, buf, nread);
				break;
			default:
				fprintf(stderr, "fail\n");
				abort();
			}
			break;
		default:
			fprintf(stderr, "fail\n");
			abort();
		}
	}
}

static
int
sztoint(size_t sz)
{
	if (sz > INT_MAX)
		abort();
	return (int)sz;
}

static
void
stdin_thread(int unused1, void *unused2)
{
	unsigned char input[256] = {0};
	ssize_t n;
	int flags;

	(void)unused1;
	(void)unused2;

	flags = fcntl(STDIN_FILENO, F_GETFL);
	if (flags == -1)
		err(EXIT_FAILURE, "fcntl(F_GETFL)");

	if (fcntl(STDIN_FILENO, F_SETFL, flags|O_NONBLOCK))
		err(EXIT_FAILURE, "fcntl(F_SETFL)");

	for (;;) {
		n = safe_read(STDIN_FILENO, input, 256);
		fprintf(stderr, "stdin input: %.*s\n", sztoint(n), input);
	}
}

static
void
handler_thread(int fd, void *ctx_void)
{
	struct server_ctx *ctx = (struct server_ctx *)ctx_void;

	for (;;) {
		fibre_awaitfd(fd, EPOLLIN);
		handle_datagram(fd, ctx);
	}
}

static
void
interval_timer_thread(int secs, void *unused)
{
	struct timespec ts = {(time_t)secs};
	int fd;
	uint64_t expirations;
	ssize_t n;

	(void)unused;

	fd = timerfd_open(ts);
	if (fd == -1)
		err(EXIT_FAILURE, "timerfd_open");

	for (;;) {
		fibre_awaitfd(fd, EPOLLIN);

		n = read(fd, &expirations, sizeof expirations);
		if (n == -1 && errno != EAGAIN)
			err(EXIT_FAILURE, "Could not read expirations");

		warnx("Heartbeat %lu", expirations);
	}
}


static
void
serve(int argc, char **argv)
{
	struct addrinfo hints, *result, *rp;
	struct server_ctx ctx = {0};
	const char *host, *port;
	int fd = -1, gai;

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	if (peertable_init(&ctx.peertable))
		err(EXIT_FAILURE, "Couldn't initialise peer table.");

	stbds_sh_new_arena(ctx.namestable);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	gai = getaddrinfo(host, port, &hints, &result);
	if (gai != 0)
		(gai == EAI_SYSTEM ? err : errx)
			(EXIT_FAILURE, "getaddrinfo: %s", gai_strerror(gai));

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, SOCK_NONBLOCK|rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fd);
	}
	if (fd == -1)
		err(EXIT_FAILURE, "Invalid file descriptor");

	freeaddrinfo(result);

	if (rp == NULL)
		err(EXIT_FAILURE, "Couldn't bind to socket");

	fibre_go(FP_HIGH, interval_timer_thread, 10, NULL);

	fibre_go(FP_NORMAL, stdin_thread, 0, NULL);

	/* this is safe, because serve()'s stack frame will live forever.
	 * However, in general it is not safe to pass pointers into the stack
	 * as fibre_go arguments unless they are somehow arranged to be yielded
	 * to before the function calling fibre_go returns.
	 */
	fibre_go(FP_NORMAL, handler_thread, fd, &ctx);

	fibre_return();

	exit(EXIT_SUCCESS);
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

	if (proof_check(response, challenge, signing_key, difficulty)) {
		fprintf(stderr, "Could not verify challenge response.\n");
		exit(EXIT_FAILURE);
	} else {
		fprintf(stderr, "Verified proof of work.\n");
		exit(EXIT_SUCCESS);
	}
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

	exit(EXIT_SUCCESS);
}

static intptr_t counter;

static
void
test_fibre(int j, void *unused)
{
	static int i;
	struct timespec ts = {0};

	(void)unused;

	printf("Hello from %d %d (%d)\n", j, fibre_current(), i);
	if (++i < 3) {
		/* printf("Sleep1 from %d %d (%d)!\n", j, fibre_current(), i); */
		/* ts.tv_sec = 1; */
		/* fibre_sleep(&ts); */
		printf("Go1 from %d %d (%d)!\n", j, fibre_current(), i);
		fibre_go(FP_NORMAL, test_fibre, counter++, NULL);
		printf("Sleep2 from %d %d (%d)!\n", j, fibre_current(), i);
		ts.tv_sec = 2;
		fibre_sleep(&ts);
		printf("Go2 from %d %d (%d)!\n", j, fibre_current(), i);
		fibre_go(FP_NORMAL, test_fibre, counter++, NULL);
	}
	printf("Goodbye from %d %d (%d)\n", j, fibre_current(), i);
	fibre_return();
}

static
void
test_fibre2(int unused1, void *unused2)
{
	int fd;
	ssize_t nread;
	char buf[256] = {0};

	(void)unused1;
	(void)unused2;

	fd = open("example.txt", O_RDWR|O_NONBLOCK);
	if (fd == -1)
		err(EXIT_FAILURE, "Could not open `%s'", "example.txt");

	do nread = fibre_read(fd, buf, 255);
	while (nread == -1 && errno == EINTR);
	if (nread == -1)
		err(EXIT_FAILURE, "Could not read from `%s'", "example.txt");

	displaykey("buf", (void *)buf, 256);
}

static
void
fibre(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	fibre_go(FP_NORMAL, test_fibre, counter++, NULL);
	fibre_go(FP_HIGH, test_fibre2, 0, NULL);
	while (fibre_yield());
	fibre_return();

	exit(EXIT_SUCCESS);
}

void
usage(void)
{
	fprintf(stderr, "usage: %s (k[eygen] | p[roof] | d[aemon) HOST PORT)\n",
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
	fibre_init(STACK_SIZE);

	switch (argv[1][0]) {
		case 'a': alice(argc, argv); break;
		case 'b': bob(argc, argv); break;
		case 'd': serve(argc, argv); break;
		case 'f': fibre(argc, argv); break;
		case 'k': keygen(argc, argv); break;
		case 'p': proof(argc, argv); break;
		default:  usage();
	}

	/* the functions dispatched above should not return */
	exit(EXIT_FAILURE);
}
