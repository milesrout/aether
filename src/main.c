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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>

#include "monocypher.h"
#include "optparse.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

#include "err.h"
#include "hkdf.h"
#include "util.h"
#include "queue.h"
#include "packet.h"
#include "proof.h"
#include "msg.h"
#include "peertable.h"
#include "ident.h"
#include "chat.h"
#include "io.h"
#include "main.h"
#include "fibre.h"
#include "timer.h"
#include "persist.h"

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

extern char *__progname;

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

struct stored_message {
	uint8_t  isk[32];
	uint16_t size;
	uint8_t *data;
};

struct userinfo {
	uint8_t ik[32];
	uint8_t spk[32];
	uint8_t spk_sig[64];
	struct  key *opks;
	struct  stored_message *letterbox;
	char   *username;
	struct  peer *peer;
};

struct userkv {
	struct key key;
	struct userinfo value;
};

struct usernamev {
	char  *key;
	struct key value;
};

struct server_ctx {
	struct peertable peertable;
	struct userkv *table;
	struct usernamev *namestable;
	struct msgqueuehead spares;
	int    fd;

};

struct handler_ctx {
	struct server_ctx *ctx;
	struct peer *peer;
	int    should_quit;
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
print_table(struct userkv *table, int print_opks)
{
	ptrdiff_t len, i;
	struct userkv *el;

	len = stbds_hmlen(table);
	printf("table length = %ld\n", len);

	for (i = 0; i < len; i++) {
		ptrdiff_t arrlen, j;

		printf("el = %p\n", (void *)(el = &table[i]));

		if (el->value.peer)
			printf("host = %s:%s\n", el->value.peer->host,
				el->value.peer->service);

		if (el->value.username)
			printf("username = %s\n", el->value.username);

		displaykey_short("isk", el->key.data, 32);
		displaykey_short("ik", el->value.ik, 32);
		displaykey_short("spk", el->value.spk, 32);
		displaykey_short("spksig", el->value.spk_sig, 64);

		if (print_opks) {
			arrlen = stbds_arrlen(el->value.opks);
			for (j = 0; j < arrlen; j++)
				displaykey_short("opk", el->value.opks[j].data, 32);
		}

		arrlen = stbds_arrlen(el->value.letterbox);
		for (j = 0; j < arrlen; j++) {
			displaykey_short("sender", el->value.letterbox[j].isk, 32);
			displaykey("the message", el->value.letterbox[j].data, el->value.letterbox[j].size);
		}
	}
}

/*
static
const char *
send_packet_to(struct peer *peer, int fd, uint8_t *buf, size_t size)
{
	uint8_t *text = PACKET_TEXT(buf);
	const char *error;
	uint8_t proto = text[0], type = text[1];
	const char *proto_str = msg_proto(proto);
	const char *type_str = msg_type(proto, type);

	packet_lock(&peer->state.ps, buf, size);
	error = safe_sendto(fd, buf, PACKET_BUF_SIZE(size),
		(struct sockaddr *)&peer->addr, peer->addr_len);
	crypto_wipe(buf, PACKET_BUF_SIZE(size));

	printf("-> %zu\t%s:%s\t%d/%d\t%s/%s\n", PACKET_BUF_SIZE(size),
		peer->host, peer->service, proto, type, proto_str, type_str);

	return error;
}
*/

static
int
parse_register(const uint8_t **pname, uint8_t *pnamelen,
		const uint8_t *text, size_t size)
{
	if (persist_load8(pnamelen, &text, &size)) return -1;
	if (persist_loadbytes_ref(pname, *pnamelen, &text, &size)) return -1;

	return 0;
}

static
int
userdb_register(struct handler_ctx *hctx, struct peer *peer,
		const uint8_t *name)
{
	struct server_ctx *ctx = hctx->ctx;
	struct userinfo ui = {0};
	struct userkv *kv;
	struct key isk;

	packet_get_iskc(isk.data, &peer->state.ps);
	if (kv = stbds_hmgetp_null(ctx->table, isk))
		return -1;

	if (stbds_shgetp_null(ctx->namestable, (intptr_t)name))
		return -1;

	crypto_from_eddsa_public(ui.ik, isk.data);
	stbds_shput(ctx->namestable, (intptr_t)name, isk);
	ui.username = ctx->namestable[stbds_shlen(ctx->namestable) - 1].key;
	ui.peer = peer;
	stbds_hmput(ctx->table, isk, ui);

	return 0;
}

static
int
parse_spksub(const uint8_t **spk, const uint8_t **spk_sig,
		const uint8_t *text, size_t size)
{
	if (persist_loadbytes_ref(spk,     32, &text, &size)) return -1;
	if (persist_loadbytes_ref(spk_sig, 64, &text, &size)) return -1;

	return 0;
}


static
int
userdb_spksub(struct handler_ctx *hctx, struct peer *peer,
		const uint8_t spk[32], const uint8_t spk_sig[64])
{
	struct server_ctx *ctx = hctx->ctx;
	struct userkv *kv;
	struct key isk;

	packet_get_iskc(isk.data, &peer->state.ps);
	if (!(kv = stbds_hmgetp_null(ctx->table, isk)))
		return -1;

	if (check_key(isk.data, "AIBS", spk, spk_sig))
		return -1;

	memcpy(kv->value.spk,     spk,     32);
	memcpy(kv->value.spk_sig, spk_sig, 64);

	return 0;
}

static
int
parse_opkssub(const uint8_t **opks, uint8_t *count,
		const uint8_t *text, size_t size)
{
	if (persist_load8(count, &text, &size)) return -1;
	if (persist_loadbytes_ref(opks, (*count)*32, &text, &size)) return -1;

	return 0;
}

static
int
userdb_opkssub(struct handler_ctx *hctx, struct peer *peer,
		uint8_t opk_count, const uint8_t *opks)
{
	struct server_ctx *ctx = hctx->ctx;
	struct userkv *kv;
	struct key key;
	int i;

	packet_get_iskc(key.data, &peer->state.ps);
	if (!(kv = stbds_hmgetp_null(ctx->table, key)))
		return -1;

	stbds_arrsetcap(kv->value.opks, opk_count);
	for (i = 0; i < opk_count; i++) {
		memcpy(key.data, opks + (32 * i), 32);
		stbds_arrput(kv->value.opks, key);
	}

	return 0;
}

static
int
parse_lookup(const uint8_t **pname, uint8_t *pnamelen,
		const uint8_t *text, size_t size)
{
	if (persist_load8(pnamelen, &text, &size)) return -1;
	if (persist_loadbytes_ref(pname, *pnamelen, &text, &size)) return -1;

	return 0;
}

static
void
userdb_lookup(struct handler_ctx *hctx, uint8_t isk[32], const uint8_t *name)
{
	struct server_ctx *ctx = hctx->ctx;
	struct usernamev *v;

	v = stbds_shgetp_null(ctx->namestable, (intptr_t)name);
	if (v) memcpy(isk, v->value.data, 32);
	else   memset(isk, '\0', 32);
}

static
int
parse_keyreq(const uint8_t **isk, const uint8_t *text, size_t size)
{
	if (persist_loadbytes_ref(isk, 32, &text, &size)) return -1;
	return 0;
}

static
void
userdb_keyreq(struct handler_ctx *hctx, uint8_t spk[32], uint8_t spk_sig[64],
		uint8_t opk[32], const uint8_t *isk)
{
	struct server_ctx *ctx = hctx->ctx;
	struct key kisk;
	struct userkv *kv;
	struct userinfo blank = {0}, *value = &blank;
	struct key kopk = {0};

	memcpy(kisk.data, isk, 32);
	if (!(kv = stbds_hmgetp_null(ctx->table, kisk))) {
		memset(spk, 0, 32);
		memset(spk_sig, 0, 64);
		memset(opk, 0, 32);
		return;
	}

	value = &kv->value;
	memcpy(spk, value->spk, 32);
	memcpy(spk_sig, value->spk_sig, 64);

	if (stbds_arrlen(value->opks) > 0)
		kopk = stbds_arrpop(value->opks);
	else
		crypto_wipe(kopk.data, 32);
	memcpy(opk, kopk.data, 32);
}

/*
static
const char *
handle_rlookup(struct handler_ctx *hctx, struct qmsg *qmsg)
{
	uint8_t *text = PACKET_TEXT(qmsg->buf);
	size_t text_size = PACKET_TEXT_SIZE(BUFSZ);
	size_t size = PACKET_TEXT_SIZE(qmsg->size);
	struct peer *peer = hctx->peer;
	struct server_ctx *ctx = hctx->ctx;
	struct ident_rlookup_msg *msg = (struct ident_rlookup_msg *)text;
	struct key isk;
	struct userkv *kv;
	char blankusername[] = "";
	struct userinfo blank = {.username = blankusername}, *value = &blank;

	if (size < IDENT_RLOOKUP_MSG_SIZE)
		goto reply;

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		goto reply;

	value = &kv->value;

reply:
	size = ident_rlookup_rep_init(text, text_size,
		value->username);
	return send_packet_to(peer, ctx->fd, qmsg->buf, size);
}

static
const char *
handle_keyreq(struct handler_ctx *hctx, struct qmsg *qmsg)
{
	uint8_t *text = PACKET_TEXT(qmsg->buf);
	size_t text_size = PACKET_TEXT_SIZE(BUFSZ);
	size_t size = PACKET_TEXT_SIZE(qmsg->size);
	struct peer *peer = hctx->peer;
	struct server_ctx *ctx = hctx->ctx;
	struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)text;
	struct key isk;
	struct userkv *kv;
	struct userinfo blank = {0}, *value = &blank;
	struct key opk = {0};

	if (size < IDENT_KEYREQ_MSG_SIZE)
		goto reply;

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		goto reply;

	value = &kv->value;

	if (stbds_arrlen(value->opks) > 0)
		opk = stbds_arrpop(value->opks);
	else
		crypto_wipe(opk.data, 32);

reply:
	size = ident_keyreq_rep_init(text, text_size,
		value->spk, value->spk_sig, opk.data);
	return send_packet_to(peer, ctx->fd, qmsg->buf, size);
}

static
const char *
handle_unknown(struct handler_ctx *hctx, struct qmsg *qmsg)
{
	uint8_t *text = PACKET_TEXT(qmsg->buf);
	size_t text_size = PACKET_TEXT_SIZE(BUFSZ);
	struct peer *peer = hctx->peer;
	struct server_ctx *ctx = hctx->ctx;
	size_t size;

	(void)ctx;

	size = msg_nack_init(text, text_size);
	return send_packet_to(peer, ctx->fd, qmsg->buf, size);
}

static
const char *
handle_goodbye(struct handler_ctx *hctx, struct qmsg *qmsg)
{
	uint8_t *text = PACKET_TEXT(qmsg->buf);
	size_t text_size = PACKET_TEXT_SIZE(BUFSZ);
	size_t size = PACKET_TEXT_SIZE(qmsg->size);
	struct peer *peer = hctx->peer;
	struct server_ctx *ctx = hctx->ctx;
	const char *error;
	struct userkv *kv;
	struct key isk;

	if (size < CHAT_GOODBYE_MSG_SIZE)
		goto reply;

	packet_get_iskc(isk.data, &peer->state.ps);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		goto reply;

	assert(kv->value.peer);
	peer_del(&ctx->peertable, kv->value.peer);
	kv->value.peer = NULL;

reply:
	size = chat_goodbye_ack_init(text, text_size, NULL);
	error = send_packet_to(peer, ctx->fd, qmsg->buf, size);
	hctx->should_quit = 1;
	return error;
}

static
const char *
handle_fetch(struct handler_ctx *hctx, struct qmsg *qmsg)
{
	uint8_t *text = PACKET_TEXT(qmsg->buf);
	size_t text_size = PACKET_TEXT_SIZE(BUFSZ);
	size_t size = PACKET_TEXT_SIZE(qmsg->size);
	struct peer *peer = hctx->peer;
	struct server_ctx *ctx = hctx->ctx;
	int msgcount = 0;
	ptrdiff_t arrlen;
	/1* uint16_t slack; *1/
	struct key isk;
	struct userkv *kv;
	struct stored_message smsg;
	size_t totalmsglength;

	if (size < CHAT_FETCH_MSG_SIZE)
		goto reply;

	packet_get_iskc(isk.data, &peer->state.ps);
	if (!(kv = stbds_hmgetp_null(ctx->table, isk)))
		goto reply;

	/1* TODO: set to maximum value that makes total packet size <= 64k *1/
	/1* slack = 32768; *1/

	/1* for now, fetch only 1 message at a time *1/
	arrlen = stbds_arrlen(kv->value.letterbox);
	if (arrlen == 0)
		goto reply;

	smsg = kv->value.letterbox[0];
	stbds_arrdel(kv->value.letterbox, 0);
	msgcount = 1;

reply:
	totalmsglength = msgcount == 0 ? 0 : smsg.size + 34;
	size = chat_fetch_rep_init(text, text_size, msgcount, totalmsglength);

	{
		struct chat_fetch_reply_msg *msg = (struct chat_fetch_reply_msg *)text;

		if (msgcount == 1) {
			struct chat_fetch_content_msg *innermsg = (struct chat_fetch_content_msg *)msg->messages;
			store16_le(innermsg->len, smsg.size);
			memcpy(innermsg->isk,  smsg.isk,  32);
			memcpy(innermsg->text, smsg.data, smsg.size);
		}
	}

	return send_packet_to(peer, ctx->fd, qmsg->buf, size);
}

static
const char *
handle_forward(struct handler_ctx *hctx, struct qmsg *qmsg)
{
	uint8_t *text = PACKET_TEXT(qmsg->buf);
	size_t text_size = PACKET_TEXT_SIZE(BUFSZ);
	size_t size = PACKET_TEXT_SIZE(qmsg->size);
	struct peer *peer = hctx->peer;
	struct server_ctx *ctx = hctx->ctx;
	struct chat_forward_msg *msg = (struct chat_forward_msg *)text;
	struct chat_fetch_reply_msg *repmsg;
	struct chat_fetch_content_msg *innermsg;
	struct userkv *kv;
	struct stored_message smsg;
	struct key isk;
	int result = 1;
	uint16_t message_size;
	size_t repsize, totalmsglength;
	const char *error;

	if (size < CHAT_FORWARD_MSG_BASE_SIZE)
		goto reply;

	if (msg->message_count != 1)
		goto reply;

	if (size < CHAT_FORWARD_MSG_BASE_SIZE + 2)
		goto reply;

	message_size = load16_le(msg->messages);
	if (size < CHAT_FORWARD_MSG_SIZE(2 + message_size))
		goto reply;

	memcpy(isk.data, msg->isk, 32);
	if ((kv = stbds_hmgetp_null(ctx->table, isk)) == NULL)
		goto reply;

	result = 0;
	if (kv->value.peer != NULL) {
		repmsg = (struct chat_fetch_reply_msg *)text;
		innermsg = (struct chat_fetch_content_msg *)repmsg->messages;

		memmove(innermsg->text, msg->messages + 2, message_size);

		totalmsglength = message_size + 34;
		repsize = chat_fetch_rep_init(text, text_size, 1, totalmsglength);
		repmsg->msg.type = CHAT_IMMEDIATE;

		store16_le(innermsg->len, message_size);
		packet_get_iskc(innermsg->isk, &peer->state.ps);

		error = send_packet_to(kv->value.peer, ctx->fd, qmsg->buf, repsize);
		if (!error)
			goto reply;
	}

	smsg.data = malloc(message_size);
	if (smsg.data == NULL)
		return errnowrap("can't allocate stored message");

	packet_get_iskc(smsg.isk, &peer->state.ps);
	memcpy(smsg.data, msg->messages + 2, message_size);
	smsg.size = message_size;

	crypto_wipe(qmsg->buf, BUFSZ);

	stbds_arrpush(kv->value.letterbox, smsg);

reply:
	repsize = chat_forward_ack_init(text, text_size, result);
	return send_packet_to(peer, ctx->fd, qmsg->buf, repsize);
}
*/

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
STAILQ_HEAD(hshakeqh, hmsg);
struct hshake_ctx {
	struct server_ctx *ctx;
	struct hshakeqh hshakeq;
	struct hshakeqh spares;
	int    eventfd;
};
struct hmsg {
	struct qmsg *qmsg;
	struct peer *peer;
	STAILQ_ENTRY(hmsg) q;
};

static void
handle_peer(long ctx_long, void *peer_void);

static
void
handle_hshakes(long unused, void *hctx_void)
{
	struct hshake_ctx *hctx = hctx_void;
	struct server_ctx *ctx = hctx->ctx;
	const char *error;
	struct hmsg *hmsg;
	struct peer *peer;
	struct qmsg *qmsg;
	struct userkv *kv;
	struct key isk;
	long events;
	ssize_t n;

	(void)unused;

	for (;;) {
		while (hmsg = STAILQ_FIRST(&hctx->hshakeq)) {
			STAILQ_REMOVE_HEAD(&hctx->hshakeq, q);

			peer = hmsg->peer;
			qmsg = hmsg->qmsg;

			STAILQ_INSERT_HEAD(&hctx->spares, hmsg, q);

			printf("<- %zu\t", qmsg->size);

			packet_hshake_dprepare(&peer->state.ps,
				isks, isks_prv,
				iks, iks_prv,
				NULL);

			if (peer_getnameinfo(peer))
				printf("unknown host and port: ");
			else
				printf("%s:%s\t", peer->host, peer->service);

			if (packet_hshake_dcheck(&hmsg->peer->state.ps, hmsg->qmsg->buf)) {
				printf("\tHSHAKE/UNKNOWN\n");
				crypto_wipe(qmsg->buf, BUFSZ);
				STAILQ_INSERT_HEAD(&hctx->ctx->spares, qmsg, q);
				continue;
			}

			printf("\tHSHAKE/HELLO\n");
			crypto_wipe(hmsg->qmsg->buf, PACKET_HELLO_SIZE);

			packet_hshake_dreply(&hmsg->peer->state.ps, hmsg->qmsg->buf);
			error = safe_sendto(ctx->fd, qmsg->buf, PACKET_REPLY_SIZE,
				(struct sockaddr *)&peer->addr,
				peer->addr_len);
			crypto_wipe(qmsg->buf, PACKET_REPLY_SIZE);
			STAILQ_INSERT_HEAD(&hctx->ctx->spares, qmsg, q);
			if (error)
				err(1, "safe_sendto: %s", error);

			peer->status = PEER_ACTIVE;
			printf("-> %zu\t%s:%s\t\tHSHAKE/REPLY\n",
				PACKET_REPLY_SIZE, peer->host, peer->service);

			packet_get_iskc(isk.data, &peer->state.ps);
			if (kv = stbds_hmgetp_null(ctx->table, isk)) {
				kv->value.peer = peer;
			}

			fibre_go(FP_NORMAL, handle_peer, (long)ctx, peer);
		}

		do n = fibre_read(hctx->eventfd, &events, 8);
		while (n == -1 && errno == EINTR);
	}
}

/* static */
/* const char * */
/* handle_packet(struct handler_ctx *ctx, struct peer *peer, struct qmsg *qmsg) */
/* { */
/* 	uint8_t *buf, *text; */
/* 	size_t size, nread; */
/* 	struct msg *msg; */

/* 	buf = qmsg->buf; */
/* 	nread = qmsg->size; */
/* 	text = PACKET_TEXT(buf); */
/* 	size = PACKET_TEXT_SIZE(nread); */

/* 	if (packet_unlock(&peer->state.ps, buf, nread)) */
/* 		return "could not unlock packet"; */

/* 	printf("<- %zu\t", qmsg->size); */
/* 	if (peer_getnameinfo(peer)) */
/* 		printf("unknown host and port: "); */
/* 	else */
/* 		printf("%s:%s\t", peer->host, peer->service); */

/* 	if (size >= sizeof(struct msg)) { */
/* 		msg = (struct msg *)text; */
/* 		printf("%d/%d\t%s/%s\n", msg->proto, msg->type, */
/* 			msg_proto(msg->proto), msg_type(msg->proto, msg->type)); */
/* 		switch (msg->proto) { */
/* 		case PROTO_MSG: */
/* 			switch (msg->type) { */
/* 			case MSG_ACK: */
/* 				/1* record_as_acked(); *1/ */
/* 				return NULL; */
/* 			case MSG_NACK: */
/* 				/1* if (we_still_have_it) *1/ */
/* 				/1* 	send_it(); *1/ */
/* 				/1* else *1/ */
/* 				/1* 	dunno(); *1/ */
/* 				return NULL; */
/* 			case MSG_UNACK: */
/* 				/1* if (we_have_received_it) *1/ */
/* 				/1* 	send_ack(); *1/ */
/* 				/1* else *1/ */
/* 				/1* 	send_nack(); *1/ */
/* 				return NULL; */
/* 			default: */
/* 				goto error; */
/* 			} */
/* 		case PROTO_IDENT: */
/* 			switch (msg->type) { */
/* 			case IDENT_REGISTER_MSG: */
/* 				return handle_register(ctx, qmsg); */
/* 			case IDENT_SPKSUB_MSG: */
/* 				return handle_spksub(ctx, qmsg); */
/* 			case IDENT_OPKSSUB_MSG: */
/* 				return handle_opkssub(ctx, qmsg); */
/* 			case IDENT_LOOKUP_MSG: */
/* 				return handle_lookup(ctx, qmsg); */
/* 			case IDENT_RLOOKUP_MSG: */
/* 				return handle_rlookup(ctx, qmsg); */
/* 			case IDENT_KEYREQ_MSG: */
/* 				return handle_keyreq(ctx, qmsg); */
/* 			default: */
/* 				goto error; */
/* 			} */
/* 		case PROTO_CHAT: */
/* 			switch (msg->type) { */
/* 			case CHAT_GOODBYE_MSG: */
/* 				return handle_goodbye(ctx, qmsg); */
/* 			case CHAT_FETCH_MSG: */
/* 				return handle_fetch(ctx, qmsg); */
/* 			case CHAT_FORWARD_MSG: */
/* 				return handle_forward(ctx, qmsg); */
/* 			default: */
/* 				goto error; */
/* 			} */
/* 		default: */
/* 			goto error; */
/* 		} */
/* 	} */

/* error: */
/* 	printf("UNKNOWN\n"); */
/* 	return handle_unknown(ctx, qmsg); */
/* } */
int
ident_register_ack(struct msg_state *state, uint64_t id, int result);
int
ident_spksub_ack(struct msg_state *state, uint64_t id, int result);

static
void
handle_peer(long sctx_long, void *peer_void)
{
	struct server_ctx *sctx = (void *)sctx_long;
	struct peer *peer = peer_void;
	struct handler_ctx ctx = {sctx, peer};
	size_t len, descsize, desclen;
	uint8_t buf[BUFSZ];
	char *desc = NULL;
	
	for (;;) {
		struct qmsg *qmsg;
		uint64_t events;
		ssize_t n;

		while (!ctx.should_quit && (qmsg = STAILQ_FIRST(&peer->recvq))) {
			struct msg_event *ev = NULL;
			int r;

			STAILQ_REMOVE_HEAD(&peer->recvq, q);

			printf("<- %zu\t", qmsg->size);
			if (peer_getnameinfo(peer))
				printf("unknown host and port: ");
			else
				printf("%s:%s\t", peer->host, peer->service);

			r = msg_recv(&peer->state, qmsg->buf, qmsg->size);
			if (r) errx(1, "msg_recv");

			while (msg_next_event(&peer->state, &ev)) {
				struct msg_buf *msgbuf = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"

				/* fprintf(stderr, "handling event: %d\n", ev->type); */
				if (ev->proto == PROTO_IDENT) {
					switch (ev->type) {
					case IDENT_REGISTER_MSG: {
						const uint8_t *name;
						uint8_t namelen;
						if (parse_register(&name, &namelen, ev->text, ev->len))
							continue;
						r = userdb_register(&ctx, peer, name);
						msgbuf = malloc(sizeof *msgbuf);
						if (!msgbuf) err(1, "out of memory");
						n = ident_register_ack_init(msgbuf->buf, MSG_BUFSZ,
							0, ev->id, !!r);
						if (n == -1) errx(1, "logical error");
						msgbuf->len = n;
						STAILQ_INSERT_TAIL(&peer->state.sendq, msgbuf, bufq);
						break;
					}
					case IDENT_SPKSUB_MSG: {
						const uint8_t *spk, *spk_sig;
						if (parse_spksub(&spk, &spk_sig, ev->text, ev->len))
							continue;
						r = userdb_spksub(&ctx, peer, spk, spk_sig);
						msgbuf = malloc(sizeof *msgbuf);
						if (!msgbuf) err(1, "out of memory");
						n = ident_spksub_ack_init(msgbuf->buf, MSG_BUFSZ,
							0, ev->id, !!r);
						if (n == -1) errx(1, "logical error");
						msgbuf->len = n;
						STAILQ_INSERT_TAIL(&peer->state.sendq, msgbuf, bufq);
						break;
					}
					case IDENT_OPKSSUB_MSG: {
						const uint8_t *opks;
						uint8_t opk_count;
						if (parse_opkssub(&opks, &opk_count, ev->text, ev->len))
							continue;
						r = userdb_opkssub(&ctx, peer, opk_count, opks);
						msgbuf = malloc(sizeof *msgbuf);
						if (!msgbuf) err(1, "out of memory");
						n = ident_opkssub_ack_init(msgbuf->buf, MSG_BUFSZ,
							0, ev->id, !!r);
						if (n == -1) errx(1, "logical error");
						msgbuf->len = n;
						STAILQ_INSERT_TAIL(&peer->state.sendq, msgbuf, bufq);
						break;
					}
					case IDENT_LOOKUP_MSG: {
						const uint8_t *name;
						uint8_t namelen;
						uint8_t isk[32];
						if (parse_lookup(&name, &namelen, ev->text, ev->len))
							continue;
						userdb_lookup(&ctx, isk, name);
						msgbuf = malloc(sizeof *msgbuf);
						if (!msgbuf) err(1, "out of memory");
						n = ident_lookup_rep_init(msgbuf->buf, MSG_BUFSZ,
							0, ev->id, isk);
						if (n == -1) errx(1, "logical error");
						msgbuf->len = n;
						STAILQ_INSERT_TAIL(&peer->state.sendq, msgbuf, bufq);
						break;
					}
					case IDENT_KEYREQ_MSG: {
						const uint8_t *isk;
						uint8_t spk[32], spk_sig[64], opk[32];
						if (parse_keyreq(&isk, ev->text, ev->len))
							continue;
						userdb_keyreq(&ctx, spk, spk_sig, opk, isk);
						msgbuf = malloc(sizeof *msgbuf);
						if (!msgbuf) err(1, "out of memory");
						n = ident_keyreq_rep_init(msgbuf->buf, MSG_BUFSZ,
							0, ev->id, spk, spk_sig, opk);
						if (n == -1) errx(1, "logical error");
						msgbuf->len = n;
						STAILQ_INSERT_TAIL(&peer->state.sendq, msgbuf, bufq);
						break;
					}
					default:
						fprintf(stderr, "fail!\n");
						break;
					}
				}
				free(ev);
#pragma GCC diagnostic pop
			}

			while (msg_send(&peer->state, buf, BUFSZ, &len, &desc, &descsize, &desclen)) {
				const char *error;

				error = safe_sendto(sctx->fd, buf, len,
					(struct sockaddr *)&peer->addr, peer->addr_len);
				crypto_wipe(buf, len);
				printf("-> %zu\t%s:%s\t\t%.*s\n", len,
					peer->host, peer->service, (int)desclen, desc);
				*desc = 0;
				desclen = 0;

				if (error)
					err(1, "safe_sendto: %s", error);
			}

			/* error = handle_packet(&ctx, peer, qmsg); */
			/* crypto_wipe(qmsg->buf, BUFSZ); */

			STAILQ_INSERT_HEAD(&ctx.ctx->spares, qmsg, q);
		}

		if (ctx.should_quit) {
			peer_del(&ctx.ctx->peertable, peer);
			free(peer);
			return;
		}

		do n = fibre_read(peer->eventfd, &events, 8);
		while (n == -1 && errno == EINTR);
	}
}

static
const char *
enqueue_hshake(struct hshake_ctx *hctx, struct peer_init *pi, struct qmsg *qmsg)
{
	struct peer *peer;
	struct hmsg *hmsg;

	peer = peer_add(&hctx->ctx->peertable, pi);
	if (peer == NULL)
		return "failed to add peer to peertable";

	if (hmsg = STAILQ_FIRST(&hctx->spares))
		STAILQ_REMOVE_HEAD(&hctx->spares, q);
	else if ((hmsg = malloc(sizeof *hmsg)) == NULL)
		return "out of memory";

	hmsg->qmsg = qmsg;
	hmsg->peer = peer;

	STAILQ_INSERT_TAIL(&hctx->hshakeq, hmsg, q);
	if (eventfd_write(hctx->eventfd, 1))
		return errnowrap("can't signal eventfd");

	return NULL;
}

static
const char *
enqueue_packet(struct peer *peer, struct qmsg *qmsg)
{
	STAILQ_INSERT_TAIL(&peer->recvq, qmsg, q);
	if (eventfd_write(peer->eventfd, 1))
		return errnowrap("can't signal eventfd");

	return NULL;
}

static
const char *
handle_datagram(int fd, struct hshake_ctx *hctx)
{
	struct peer_init pi = {0};
	struct peer *peer;
	const char *error;
	struct qmsg *qmsg;

	if (qmsg = STAILQ_FIRST(&hctx->ctx->spares))
		STAILQ_REMOVE_HEAD(&hctx->ctx->spares, q);
	else if ((qmsg = malloc(sizeof *qmsg)) == NULL)
		return "out of memory";

	pi.addr_len = sizeof(pi.addr);
	error = safe_recvfrom(&qmsg->size, fd, qmsg->buf, BUFSZ,
		(struct sockaddr *)&pi.addr, &pi.addr_len);
	if (error) return error;

	peer = peer_getbyaddr(&hctx->ctx->peertable,
		(struct sockaddr *)&pi.addr, pi.addr_len);
	if (peer == NULL)
		return enqueue_hshake(hctx, &pi, qmsg);

	if (qmsg->size > PACKET_BUF_SIZE(0))
		return enqueue_packet(peer, qmsg);

	return NULL;
}

static
const char *
user_input(struct server_ctx *ctx)
{
	char *buf = NULL;
	size_t size;
	ssize_t len;
	int flags;
	const char *error = NULL;

	flags = fcntl(STDIN_FILENO, F_GETFL);
	if (flags == -1)
		return errnowrap("fcntl(F_GETFL)");

	if (fcntl(STDIN_FILENO, F_SETFL, flags|O_NONBLOCK))
		return errnowrap("fcntl(F_SETFL)");

	for (;;) {
		do {
			fibre_awaitfd(STDIN_FILENO, EPOLLIN),
			len = getline(&buf, &size, stdin);
		} while (len == -1 && errno == EAGAIN);
		if (len == -1) {
			error = errnowrap("getline");
			goto end;
		}

		buf[len - 1] = '\0';

		if (!strcmp(buf, "/quit"))
			goto end;

		if (!strcmp(buf, "/users"))
			print_table(ctx->table, 0);
		else if (!strcmp(buf, "/opks"))
			print_table(ctx->table, 1);
		else if (!strcmp(buf, "/names"))
			print_nametable(ctx->namestable);
		else
			printf("?\n");
	}

end:
	if (buf) free(buf);
	return error;
}

static
const char *
interval_timer(int secs)
{
	struct timespec ts = {(time_t)secs};
	int fd;
	uint64_t expirations;
	ssize_t n;

	fd = timerfd_open(ts);
	if (fd == -1)
		return "timerfd_open";

	for (;;) {
		fibre_awaitfd(fd, EPOLLIN);

		n = read(fd, &expirations, sizeof expirations);
		if (n == -1 && errno != EAGAIN)
			return "read";

		printf("Heartbeat\n");
	}
}

static
void
interval_timer_thread(long secs, void *unused)
{
	const char *error;

	(void)unused;

	error = interval_timer(secs);
	if (error) {
		fflush(stdout);
		errx(1, "interval_timer_thread: %s", error);
	}

	exit(0);
}

static
void
user_input_thread(long unused, void *ctx_void)
{
	const char *error;
	struct server_ctx *ctx = (struct server_ctx *)ctx_void;

	(void)unused;

	error = user_input(ctx);
	if (error) {
		fflush(stdout);
		errx(1, "user_input_thread: %s", error);
	}

	exit(0);
}

static
void
handler_thread(long fd, void *ctx_void)
{
	struct hshake_ctx *hctx = ctx_void;
	const char *error;

	for (;;) {
		fibre_awaitfd(fd, EPOLLIN);
		error = handle_datagram(fd, hctx);
		if (error) break;
	}

	if (error) {
		fflush(stdout);
		errx(1, "handler_thread: %s", error);
	}

	exit(0);

}

__attribute__((noreturn))
static
void
usage_D(const char *errmsg, int ret)
{
	if (errmsg)
		fprintf(stderr, "%s: %s:", __progname, errmsg);
	fprintf(stderr, "usage: %s -D [-b HOST] [-p PORT]\n", __progname);
	exit(ret);
}

static
const char *
serve(char **argv, int subopt)
{
	struct addrinfo hints, *result, *rp;
	struct server_ctx ctx = {0};
	struct hshake_ctx hctx = {&ctx};
	struct optparse options;
	const char *host, *port;
	char nihost[NI_MAXHOST], niserv[NI_MAXSERV];
	int fd = -1, gai;
	int option;

	optparse_init(&options, argv - 1);
	options.permute = 0;
	options.subopt = subopt;

	host = "127.0.0.1";
	port = "3443";
	while ((option = optparse(&options, "hb:p:")) != -1) {
		switch (option) {
		case 'b': host = options.optarg; break;
		case 'p': port = options.optarg; break;
		case 'h': usage_D(NULL, 0);
		default:  usage_D(options.errmsg, 1);
		}
	}

	fibre_init(SERVER_STACK_SIZE);

	if (peertable_init(&ctx.peertable))
		return "couldn't initialise peer table";

	stbds_sh_new_arena(ctx.namestable);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	gai = getaddrinfo(host, port, &hints, &result);
	if (gai != 0) {
		if (gai == EAI_SYSTEM)
			return errfmt("getaddrinfo: %s: %s", gai_strerror(gai), strerror(errno));
		else
			return errwrap("getaddrinfo", gai_strerror(gai));
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, SOCK_NONBLOCK|rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (!getnameinfo(rp->ai_addr, rp->ai_addrlen,
				nihost, NI_MAXHOST, niserv, NI_MAXSERV,
				NI_NUMERICHOST|NI_NUMERICSERV))
			fprintf(stderr, "!! %s:%s\n", nihost, niserv);
		else
			fprintf(stderr, "!! %s:%s\n", host, port);

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fd);
	}
	if (fd == -1)
		return strerror(errno);

	freeaddrinfo(result);

	if (rp == NULL)
		return errnowrap("couldn't bind to socket");

	STAILQ_INIT(&ctx.spares);
	ctx.fd = fd;
	STAILQ_INIT(&hctx.hshakeq);
	STAILQ_INIT(&hctx.spares);

	hctx.eventfd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
	if (hctx.eventfd == -1)
		return errnowrap("eventfd");

	fprintf(stderr, "fibre_go(FP_LOW, interval_timer_thread)\n");
	fibre_go(FP_LOW, interval_timer_thread, 10, NULL);

	/* this is safe, because serve()'s stack frame will live forever.
	 * However, in general it is not safe to pass pointers into the stack
	 * as fibre_go arguments unless they are somehow arranged to be yielded
	 * to before the function calling fibre_go returns.
	 */
	fprintf(stderr, "fibre_go(FP_LOW, user_input_thread)\n");
	fibre_go(FP_NORMAL, user_input_thread, 0, &ctx);
	fprintf(stderr, "fibre_go(FP_LOW, handler_thread)\n");
	fibre_go(FP_NORMAL, handler_thread, fd, &hctx);
	fprintf(stderr, "fibre_go(FP_LOW, handle_hshakes)\n");
	fibre_go(FP_LOW, handle_hshakes, 0, &hctx);

	fprintf(stderr, "calling fibre_return()\n");
	fibre_return();

	exit(0);
}

static
void
proof(void)
{
	uint8_t response[96];
	uint8_t challenge[32];
	uint8_t signing_key[32];
	uint8_t signing_key_prv[32];
	uint8_t difficulty = 24;

	randbytes(challenge, 32);
	randbytes(signing_key_prv, 32);
	crypto_sign_public_key(signing_key, signing_key_prv);

	displaykey_short("challenge", challenge, 32);
	displaykey_short("public key", signing_key, 32);
	displaykey_short("private key", signing_key_prv, 32);

	proof_solve(response, challenge, signing_key, signing_key_prv, difficulty);

	if (proof_check(response, challenge, signing_key, difficulty))
		err(1, "Could not verify challenge response");
	else
		err(0, "Verified proof of work");
}

static
void
keygen(void)
{
	uint8_t pub[32], prv[32];

	generate_kex_keypair(pub, prv);

	displaykey_short("pub", pub, 32);
	displaykey_short("prv", prv, 32);

	exit(0);
}

static intptr_t counter;

static
void
test_fibre(long j, void *unused)
{
	static int i;
	struct timespec ts = {0};

	(void)unused;

	printf("Hello from %ld %d (%d)\n", j, fibre_current(), i);
	if (++i < 3) {
		/* printf("Sleep1 from %d %d (%d)!\n", j, fibre_current(), i); */
		/* ts.tv_sec = 1; */
		/* fibre_sleep(&ts); */
		printf("Go1 from %ld %d (%d)!\n", j, fibre_current(), i);
		fibre_go(FP_NORMAL, test_fibre, counter++, NULL);
		printf("Sleep2 from %ld %d (%d)!\n", j, fibre_current(), i);
		ts.tv_sec = 2;
		fibre_sleep(&ts);
		printf("Go2 from %ld %d (%d)!\n", j, fibre_current(), i);
		fibre_go(FP_NORMAL, test_fibre, counter++, NULL);
	}
	printf("Goodbye from %ld %d (%d)\n", j, fibre_current(), i);
	fibre_return();
}

static
void
test_fibre2(long unused1, void *unused2)
{
	int fd;
	ssize_t nread;
	char buf[256] = {0};

	(void)unused1;
	(void)unused2;

	fd = open("example.txt", O_RDWR|O_NONBLOCK);
	if (fd == -1)
		err(1, "Could not open `%s'", "example.txt");

	do nread = fibre_read(fd, buf, 255);
	while (nread == -1 && errno == EINTR);
	if (nread == -1)
		err(1, "Could not read from `%s'", "example.txt");

	displaykey("buf", (void *)buf, 256);
}

static
void
fibre(void)
{
	fibre_init(1024);
	fibre_go(FP_NORMAL, test_fibre, counter++, NULL);
	fibre_go(FP_HIGH, test_fibre2, 0, NULL);
	while (fibre_yield());
	fibre_return();

	exit(0);
}

static
void
persist(char **argv, int subopt)
{
	uint8_t *buf;
	size_t size;
	const char *filename;
	ssize_t password_size;
	char *password = NULL;
	size_t password_bufsize = 0;
	struct optparse options;
	int option;
	int cmd = 0;

	optparse_init(&options, argv);
	options.permute = 0;
	options.subopt = subopt;

	filename = NULL;
	while ((option = optparse(&options, "r:w:"))) switch (option) {
		case 'r':
		case 'w':
			if (cmd)
				usage(NULL, 1);
			cmd = option;
			filename = options.optarg;
			break;
		default:
			usage(options.errmsg, 1);
			break;
	}

	if (!cmd)
		usage(NULL, 1);

	printf("password: ");
	if ((password_size = getline(&password, &password_bufsize, stdin)) == -1)
		err(1, "Could not read password from stdin");

	assert(password[password_size - 1] == '\n');
	assert(password[password_size] == '\0');
	password[password_size - 1] = '\0';
	password_size--;

	if (cmd == 'r') {
		if (persist_read(&buf, &size, filename, password, password_size))
			errx(1, "Could not load from `%s'", filename);
		displaykey("data", buf, size);
		fprintf(stderr, "%.*s\n", (int)size, buf);
	} else if (cmd == 'w') {
		buf = calloc(1, 16);
		if (buf == NULL)
			err(1, "calloc");
		memcpy(buf, "hello, world!", strlen("hello, world!") + 1);
		size = 16;
		if (persist_write(filename, buf, size, password, password_size))
			errx(1, "Could not store to `%s'", filename);
	}

	exit(0);
}

char *sgetdelim(FILE *f, size_t *len, int delim,
		char *stack, size_t stacksz,
		char **heap, size_t *heapsz);
static
void
test_sgetdelim(void)
{
	size_t len = 0, size = 0;
	char buf[8] = {0};
	char *p = NULL, *str = NULL;

	for (;;) {
		fprintf(stderr, "PRE  %zu %zu s=%p[%.*s] h=%p[%s] r=%p[%s]\n",
			len, size, buf, 8, buf, p, p, str, str);
		str = sgetdelim(stdin, &len, '\n', buf, 8, &p, &size);
		fprintf(stderr, "POST %zu %zu s=%p[%.*s] h=%p[%s] r=%p[%s]\n",
			len, size, buf, 8, buf, p, p, str, str);
	}
}

static
void
version(void)
{
	test_sgetdelim();

	fprintf(stderr, "aether version master\n");
	exit(0);
}

void
usage(const char *errmsg, int ret)
{
	if (errmsg)
		warnx("%s", errmsg);
	fprintf(stderr, "usage: %s [-hABDFKPRV]\n", __progname);
	exit(ret);
}

int
main(int argc, char **argv)
{
	const char *error = NULL;
	struct optparse options;
	uint8_t seed[8];
	int option;

	if (argc < 2)
		usage(NULL, 1);

	randbytes(seed, 8);
	stbds_rand_seed(load64_le(seed));

	optparse_init(&options, argv);
	options.permute = 0;

	if ((option = optparse(&options, "hABDFKPRV")) != -1) {
		switch (option) {
		case 'A': alice(argv + options.optind, options.subopt); break;
		case 'B': bob(argv + options.optind, options.subopt); break;
		case 'D': error = serve(argv + options.optind, options.subopt); break;
		case 'F': fibre(); break;
		case 'K': keygen(); break;
		case 'P': proof(); break;
		case 'R': persist(argv + options.optind, options.subopt); break;
		case 'V': version(); break;
		case 'h': usage(NULL, 0); break;
		default:  usage(options.errmsg, 1);
		}
	} else usage(NULL, 1);

	if (error) {
		fflush(stdout);
		errx(1, "%s", error);
	}

	/* the functions dispatched above should not return */
	usage(NULL, 1);
}
