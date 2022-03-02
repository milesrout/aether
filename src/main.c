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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

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

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

#define STACK_SIZE (256 * 1024)

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

static
int
client(int argc, char **argv)
{
	/* TODO: discover through DNS or HTTPS or something */
	/* uint8_t isks[32]; */
	int fd;
	uint8_t iskc[32], iskc_prv[32];
	uint8_t ikc[32], ikc_prv[32];
	struct packet_state state;
	const char *host, *port;

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	generate_sig_keypair(iskc, iskc_prv);
	crypto_from_eddsa_public(ikc,      iskc);
	crypto_from_eddsa_private(ikc_prv, iskc_prv);

	fd = setclientup(host, port);
	if (fd == -1)
		exit(EXIT_FAILURE);

	{
		uint8_t buf[65536];
		size_t nread;

		packet_hshake_cprepare(&state, isks, iks, iskc, iskc_prv, ikc, ikc_prv);
		packet_hshake_chello(&state, buf);
		safe_write(fd, buf, PACKET_HELLO_SIZE);
		crypto_wipe(buf, PACKET_HELLO_SIZE);

		nread = safe_read(fd, buf, PACKET_REPLY_SIZE + 1);
		if (nread != PACKET_REPLY_SIZE) {
			fprintf(stderr, "Received the wrong message.\n");
			crypto_wipe(buf, PACKET_REPLY_SIZE);
			return -1;
		}

		if (packet_hshake_cfinish(&state, buf)) {
			fprintf(stderr, "Reply message cannot be decrypted.\n");
			crypto_wipe(buf, PACKET_REPLY_SIZE);
			return -1;
		}

		crypto_wipe(buf, PACKET_REPLY_SIZE);

		memset(PACKET_TEXT(buf), 0x77, 24);
		packet_lock(&state, buf, 24);

		safe_write(fd, buf, PACKET_BUF_SIZE(24));
		crypto_wipe(buf, PACKET_BUF_SIZE(24));
		fprintf(stderr, "sent 24-byte message\n");

		nread = safe_read(fd, buf, 65536);

		while (nread > PACKET_BUF_SIZE(1)) {
			if (packet_unlock(&state, buf, nread)) {
				break;
			}

			if (nread > PACKET_BUF_SIZE(1)) {
				packet_lock(&state, buf, PACKET_TEXT_SIZE(nread) - 1);
				safe_write(fd, buf, nread - 1);
				fprintf(stderr, "sent %lu-byte message\n", PACKET_TEXT_SIZE(nread) - 1);
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
	struct packethdr *hdr = PACKET_HDR(buf);
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_register_msg *msg = (struct ident_register_msg *)text;
	struct key isk;
	struct userinfo ui = {0};
	struct userkv *kv;
	uint8_t failure = 1;

	if (size < IDENT_REGISTER_MSG_BASE_SIZE)
		errg("Registration message (%lu) is too short (%lu).",
			size, IDENT_REGISTER_MSG_BASE_SIZE);

	if (size < IDENT_REGISTER_MSG_SIZE(msg->username_len))
		errg("Registration message (%lu) is the wrong size (%lu).",
			size, IDENT_REGISTER_MSG_SIZE(msg->username_len));

	if (msg->username[msg->username_len] != '\0')
		errg("Cannot register a username that is not a valid string.");

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) != NULL) {
		if (strcmp(kv->value.username, (const char *)msg->username) == 0) {
			failure = 0;
			goto fail;
		}
		errg("Cannot register an already-registered identity key.");
	}

	if (stbds_shgetp_null(ctx->namestable, msg->username) != NULL)
		errg("Cannot register an already-registered username.");

	failure = 0;

	crypto_from_eddsa_public(ui.ik, isk.data);
	stbds_shput(ctx->namestable, msg->username, isk);
	ui.username = ctx->namestable[stbds_shlen(ctx->namestable) - 1].key;
	ui.peer = peer;
	fprintf(stderr, "username: %s\n", ui.username);
	stbds_hmput(ctx->table, isk, ui);

fail:
	size = ident_register_ack_init(PACKET_TEXT(buf), hdr->msn, failure);
	send_packet(fd, peer, buf, size);
	fprintf(stderr, "sent %lu-byte (%lu-byte) register ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
	print_nametable(ctx->namestable);
}

static
void
handle_spksub(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	struct packethdr *hdr = PACKET_HDR(buf);
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_spksub_msg *msg = (struct ident_spksub_msg *)text;
	struct key isk;
	struct userkv *kv;
	uint8_t failure = 1;

	if (size < IDENT_SPKSUB_MSG_SIZE)
		errg("Signed prekey submission message (%lu) is the wrong size (%lu).",
			size, IDENT_SPKSUB_MSG_SIZE);

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg("Can only submit a signed prekey for a registered identity.");

	if (check_key(isk.data, "AIBS", msg->spk, msg->spk_sig))
		errg("Failed signature");

	failure = 0;
	memcpy(kv->value.spk, msg->spk, 32);
	memcpy(kv->value.spk_sig, msg->spk_sig, 64);

fail:
	size = ident_spksub_ack_init(PACKET_TEXT(buf), hdr->msn, failure);
	send_packet(fd, peer, buf, size);
	fprintf(stderr, "sent %lu-byte (%lu-byte) spksub ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
}

static
void
handle_opkssub(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	struct packethdr *hdr = PACKET_HDR(buf);
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_opkssub_msg *msg = (struct ident_opkssub_msg *)text;
	struct key isk;
	struct userkv *kv;
	int i;
	uint16_t opkcount;
	uint8_t failure = 1;

	if (size < IDENT_OPKSSUB_MSG_BASE_SIZE)
		errg("One-time prekey submission message (%lu) is too short (%lu).",
			size, IDENT_OPKSSUB_MSG_BASE_SIZE);

	opkcount = load16_le(msg->opk_count);
	fprintf(stderr, "OPK count: %d\n", opkcount);
	if (size < IDENT_OPKSSUB_MSG_SIZE(opkcount))
		errg("One-time prekey submission message (%lu) is the wrong size (%lu).",
			size, IDENT_OPKSSUB_MSG_SIZE(opkcount));

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg("Can only submit one-time prekeys for a registered identity.");

	failure = 0;

	stbds_arrsetcap(kv->value.opks, opkcount);
	for (i = 0; i < opkcount; i++) {
		struct key opk;
		memcpy(opk.data, msg->opk[i], 32);
		stbds_arrput(kv->value.opks, opk);
	}

fail:
	size = ident_opkssub_ack_init(PACKET_TEXT(buf), hdr->msn, failure);
	send_packet(fd, peer, buf, size);
	fprintf(stderr, "sent %lu-byte (%lu-byte) opkssub ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
}

static
void
handle_lookup(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	struct packethdr *hdr = PACKET_HDR(buf);
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_lookup_msg *msg = (struct ident_lookup_msg *)text;
	struct key k = {0};
	uint8_t namelen;

	if (size < IDENT_LOOKUP_MSG_BASE_SIZE)
		errg("Username lookup message (%lu) is too small (%lu).",
			size, IDENT_LOOKUP_MSG_BASE_SIZE);
	namelen = msg->username_len;
	if (size < IDENT_LOOKUP_MSG_SIZE(namelen))
		errg("Username lookup message (%lu) is the wrong size (%lu).",
			size, IDENT_LOOKUP_MSG_SIZE(namelen));
	if (msg->username[namelen] != '\0')
		errg("Username lookup message is invalid.");

	k = stbds_shget(ctx->namestable, msg->username);

fail:
	size = ident_lookup_rep_init(PACKET_TEXT(buf), hdr->msn, k.data);
	send_packet(fd, peer, buf, size);
	fprintf(stderr, "sent %lu-byte (%lu-byte) lookup ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_nametable(ctx->namestable);
}

static
void
handle_reverse_lookup(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	struct packethdr *hdr = PACKET_HDR(buf);
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_reverse_lookup_msg *msg = (struct ident_reverse_lookup_msg *)text;
	struct key isk;
	struct userkv *kv;
	char blankusername[] = "";
	struct userinfo blank = {.username = blankusername}, *value = &blank;

	if (size < IDENT_REVERSE_LOOKUP_MSG_SIZE)
		errg("Username reverse-lookup message (%lu) is too small (%lu).",
			size, IDENT_REVERSE_LOOKUP_MSG_SIZE);

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg("Can only look up a username of a registered identity.");

	value = &kv->value;

fail:
	size = ident_reverse_lookup_rep_init(PACKET_TEXT(buf),
		hdr->msn, value->username);
	send_packet(fd, peer, buf, size);
	fprintf(stderr, "sent %lu-byte (%lu-byte) reverse lookup ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_nametable(ctx->namestable);
}

static
void
handle_keyreq(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	struct packethdr *hdr = PACKET_HDR(buf);
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);
	struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)text;
	struct key isk;
	struct userkv *kv;
	struct userinfo blank = {0}, *value = &blank;
	struct key opk = {0};

	if (size < IDENT_KEYREQ_MSG_SIZE)
		errg("Key bundle request message (%lu) is the wrong size (%lu).",
			size, IDENT_KEYREQ_MSG_SIZE);

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg("Can only request a key bundle for a registered identity.");

	value = &kv->value;

	if (stbds_arrlen(value->opks) > 0)
		opk = stbds_arrpop(value->opks);
	else
		crypto_wipe(opk.data, 32);

fail:
	size = ident_keyreq_rep_init(PACKET_TEXT(buf), hdr->msn,
		value->spk, value->spk_sig, opk.data);
	send_packet(fd, peer, buf, size);
	fprintf(stderr, "sent %lu-byte (%lu-byte) key request ack message\n",
		size, PACKET_BUF_SIZE(size));

	print_table(ctx->table);
}


static
void
handle_fetch(struct server_ctx *ctx, struct peer *peer, int fd, uint8_t *buf, size_t nread)
{
	struct packethdr *hdr = PACKET_HDR(buf);
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
		errg("Message-fetching message (%lu) is too small (%lu).",
			size, MSG_FETCH_MSG_SIZE);

	memcpy(isk.data, peer->state.u.rad.iskc, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		errg("Only registered identities may fetch messages.");

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
	size = msg_fetch_rep_init(text, hdr->msn, msgcount, totalmsglength);

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
	fprintf(stderr, "sent %lu-byte (%lu-byte) message fetch reply message\n",
		size, PACKET_BUF_SIZE(size));
}

struct datagram_handler_args {
	struct server_ctx *ctx;
	int fd;
};

static
void
handle_datagram(void *args_void)
{
	struct datagram_handler_args *args = args_void;
	struct server_ctx *ctx = args->ctx;
	int fd = args->fd;
	size_t nread;
	uint8_t buf[65536] = {0};
	struct peer *peer;
	struct peer_init pi = {0};

	pi.addr_len = sizeof(pi.addr);
	nread = safe_recvfrom_nonblock(fd, buf, 65536,
		&pi.addr, &pi.addr_len);

	fprintf(stderr, "Received %zu bytes. ", nread);

	peer = peer_getbyaddr(&ctx->peertable, sstosa(&pi.addr), pi.addr_len);
	if (peer == NULL) {
		fprintf(stderr, "Peer not found. ");
		peer = peer_add(&ctx->peertable, &pi);
		if (peer == NULL)
			errx(EXIT_FAILURE, "Failed to add peer to peertable.");
	} else fprintf(stderr, "Peer in table. ");

	if (peer_getnameinfo(peer))
		fprintf(stderr, "Peer on unknown host and port. ");
	else
		fprintf(stderr, "Peer %s on port %s. ",
			peer->host, peer->service);

	fprintf(stderr, "Peer status: %d\n", peer->status);

	/* This is either a HELLO message from a new peer or a message
	 * from a peer that isn't new but has just changed addresses
	 * that just happens to be exactly PACKET_HELLO_SIZE bytes.
	 */
	if (peer->status == PEER_NEW && nread == PACKET_HELLO_SIZE) {
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
			fprintf(stderr, "Peer status: %d\n", peer->status);
			return;
		}

		fprintf(stderr, "Whoops it wasn't a HELLO... at least not a valid one\n");
		/* Fall through: check if it's a real message */
	}

	/* fprintf(stderr, "nread: %lu\n", nread); */

	if (nread <= PACKET_BUF_SIZE(0))
		errx(EXIT_FAILURE, "invalid message");

	struct packethdr *hdr = PACKET_HDR(buf);
	uint8_t *text = PACKET_TEXT(buf);
	size_t size = PACKET_TEXT_SIZE(nread);

	if (packet_unlock(&peer->state, buf, nread)) {
		fprintf(stderr, "Couldn't decrypt message with size=%lu (text_size=%lu)\n",
			nread, PACKET_TEXT_SIZE(nread));
		return;
	}

	if (size >= sizeof(struct msg)) {
		struct msg *msg = (struct msg *)text;
		/* fprintf(stderr, "msg proto = %d\n", msg->proto); */
		/* fprintf(stderr, "msg type = %d\n", msg->type); */
		/* fprintf(stderr, "msg len = %d\n", load16_le(msg->len)); */
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
			case MSG_FORWARD_MSG: {
				struct msg_forward_msg *msg = (struct msg_forward_msg *)text;
				int result = 1;
				uint16_t message_size;
				struct key isk;
				struct userkv *kv;

				if (size < MSG_FORWARD_MSG_BASE_SIZE) {
					fprintf(stderr, "Message-forwarding message (%lu) is too small (%lu).\n",
						size, MSG_FORWARD_MSG_BASE_SIZE);
					goto forward_fail;
				}

				if (msg->message_count != 1) {
					fprintf(stderr, "Message-forwarding messages with more than one message within not yet supported.\n");
					goto forward_fail;
				}

				if (size < MSG_FORWARD_MSG_BASE_SIZE + 2) {
					fprintf(stderr, "Message-forwarding message (%lu) is too small (%lu).\n",
						size, MSG_FORWARD_MSG_BASE_SIZE + 2);
					goto forward_fail;
				}

				message_size = load16_le(msg->messages);
				if (size < MSG_FORWARD_MSG_SIZE(2 + message_size)) {
					fprintf(stderr, "Message-forwarding message (%lu) is the wrong size (%lu).\n",
						size, MSG_FORWARD_MSG_SIZE(2 + message_size));
					goto forward_fail;
				}

				memcpy(isk.data, msg->isk, 32);
				if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL) {
					fprintf(stderr, "Can only forward messages to a registered identity.\n");
					goto forward_fail;
				}

				result = 0;

				if (kv->value.peer == NULL) {
					struct stored_message smsg = {0};

					smsg.data = malloc(message_size);
					if (smsg.data == NULL) {
						fprintf(stderr, "Cannot allocate memory.\n");
						result = 1;
						goto forward_fail;
					}

					memcpy(smsg.isk, peer->state.u.rad.iskc, 32);
					memcpy(smsg.data, msg->messages + 2, message_size);
					smsg.size = message_size;

					crypto_wipe(buf, nread);

					stbds_arrpush(kv->value.letterbox, smsg);
				} else {
					struct msg_fetch_reply_msg *repmsg = (struct msg_fetch_reply_msg *)PACKET_TEXT(buf);
					struct msg_fetch_content_msg *innermsg = (struct msg_fetch_content_msg *)repmsg->messages;
					size_t repsize, totalmsglength;

					memmove(innermsg->text, msg->messages + 2, message_size);

					totalmsglength = message_size + 34;
					repsize = msg_fetch_rep_init(PACKET_TEXT(buf), hdr->msn, 1, totalmsglength);
					repmsg->msg.type = MSG_IMMEDIATE;

					store16_le(innermsg->len, message_size);
					memcpy(innermsg->isk,  peer->state.u.rad.iskc, 32);

					send_packet(fd, kv->value.peer, buf, repsize);
					fprintf(stderr, "sent %lu-byte (%lu-byte) immediate forwarding message\n",
						repsize, PACKET_BUF_SIZE(repsize));
				}

			forward_fail:
				{
					size_t repsize = msg_forward_ack_init(PACKET_TEXT(buf), hdr->msn, result);
					send_packet(fd, peer, buf, repsize);
					fprintf(stderr, "sent %lu-byte (%lu-byte) forward ack message\n",
						repsize, PACKET_BUF_SIZE(repsize));
				}

				break;
			}
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
void
stdin_thread(void *unused)
{
	(void)unused;
}

static
void
handler_thread(void *args_void)
{
	struct datagram_handler_args *args_ptr = args_void;
	struct datagram_handler_args args = *args_ptr;

	while (1) {
		fibre_awaitfd(args.fd, POLLIN);
		handle_datagram(&args);
	}
}

static
void
interval_timer_thread(void *ts_void)
{
	struct timespec *ts = (struct timespec *)ts_void;
	int fd, res;
	struct itimerspec timer;

	fd = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
	if (fd == -1)
		err(EXIT_FAILURE, "Could not create fd");

	timer.it_value = *ts;
	timer.it_interval = *ts;
	res = timerfd_settime(fd, 0, &timer, NULL);
	if (res == -1)
		err(EXIT_FAILURE, "Could not set timer");

	for (;;) {
		uint64_t expirations;
		ssize_t n;

		fibre_awaitfd(fd, POLLIN);

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
	struct timespec interval;
	struct server_ctx ctx = {0};
	const char *host, *port;
	int fd = -1, gai;

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	if (peertable_init(&ctx.peertable))
		err(EXIT_FAILURE, "Couldn't initialise peer table.");

	fibre_init(4096 * 256);

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
		fd = socket(rp->ai_family, rp->ai_socktype|O_NONBLOCK, rp->ai_protocol);
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

	interval.tv_sec = 10;
	interval.tv_nsec = 0;
	fibre_go(interval_timer_thread, &interval);

	fibre_go(stdin_thread, NULL);

	struct datagram_handler_args args = {&ctx, fd};
	fibre_go(handler_thread, &args);

	while (fibre_yield())
		;
	fibre_return();
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

static intptr_t counter;

static
void
test_fibre(void *_counter)
{
	static int i;
	intptr_t j = (intptr_t)_counter;
	struct timespec ts = {0};

	fprintf(stderr, "Hello from %ld %d (%d)\n", j, fibre_current(), i);
	if (++i < 3) {
		/* fprintf(stderr, "Sleep1 from %ld %d (%d)!\n", j, fibre_current(), i); */
		/* ts.tv_sec = 1; */
		/* fibre_sleep(&ts); */
		fprintf(stderr, "Go1 from %ld %d (%d)!\n", j, fibre_current(), i);
		fibre_go(test_fibre, (void *)(counter++));
		fprintf(stderr, "Sleep2 from %ld %d (%d)!\n", j, fibre_current(), i);
		ts.tv_sec = 2;
		fibre_sleep(&ts);
		fprintf(stderr, "Go2 from %ld %d (%d)!\n", j, fibre_current(), i);
		fibre_go(test_fibre, (void *)(counter++));
	}
	fprintf(stderr, "Goodbye from %ld %d (%d)\n", j, fibre_current(), i);
	fibre_return();
}

static
void
test_fibre2(void *unused)
{
	int fd;
	ssize_t nread;
	char buf[256] = {0};

	(void)unused;

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

	fibre_init(STACK_SIZE);
	fibre_go(test_fibre, (void *)(counter++));
	fibre_go(test_fibre2, NULL);
	while (fibre_yield());
	fibre_return();
}

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
		case 'a': alice(argc, argv); break;
		case 'b': bob(argc, argv); break;
		case 'c': client(argc, argv); break;
		case 'd': serve(argc, argv); break;
		case 'f': fibre(argc, argv); break;
		case 'k': keygen(argc, argv); break;
		case 'p': proof(argc, argv); break;
		default:  usage();
	}

	return 0;
}
