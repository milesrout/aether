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
#include <poll.h>
#include <stddef.h>
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
#include "timer.h"

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

static
uint8_t zero_key[32] = {0};

int handle_ident_replies(int fd, uint8_t buf[65536], struct packet_state *state, int minreplies);

int
handle_ident_replies(int fd, uint8_t buf[65536], struct packet_state *state, int minreplies)
{
	size_t nread;

	while ((nread = (minreplies ? safe_read(fd, buf, 65536) : safe_read_nonblock(fd, buf, 65536)))) {
		uint8_t *text = PACKET_TEXT(buf);
		size_t size = PACKET_TEXT_SIZE(nread);

		if (nread == 0)
			continue;

		if (nread < PACKET_BUF_SIZE(0))
			errg(fail, "Received a message that is too small.");

		if (packet_unlock(state, buf, nread))
			errg(fail, "handle_ident_replies: Message cannot be decrypted.");

		if (size >= 1) {
			struct msg *msg = (struct msg *)text;

			minreplies--;
			if (msg->proto != PROTO_IDENT)
				continue;

			switch (msg->type) {
			case IDENT_OPKSSUB_ACK: {
				struct ident_opkssub_ack_msg *msg = (void *)text;
				if (size < sizeof *msg)
					errg(fail, "OPKs submission ack message is the wrong size.");
				fprintf(stderr, "OPKs submission ack\n");
				if (msg->result)
					goto fail;
				break;
			}
			case IDENT_SPKSUB_ACK: {
				struct ident_spksub_ack_msg *msg = (void *)text;
				if (size < sizeof *msg)
					errg(fail, "SPK submission ack message is the wrong size.");
				fprintf(stderr, "SPK submission ack\n");
				if (msg->result)
					goto fail;
				break;
			}
			case IDENT_REGISTER_ACK: {
				struct ident_register_ack_msg *msg = (void *)text;
				if (size < sizeof *msg)
					errg(fail, "Registration ack message is the wrong size.");
				fprintf(stderr, "Registration submission ack\n");
				if (msg->result)
					goto fail;
				break;
			}
			default:
				fprintf(stderr, "Unrecognised message type %d\n", text[0]);
				fprintf(stderr, "(proto,type,len) = (%d,%d,%d)\n",
					msg->proto, msg->type, load16_le(msg->len));
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


/* USERNAMES */

static
int
get_username(const char **username_storage, struct packet_state *state, int fd, uint8_t isk[32])
{
	size_t size, nread;
	int result = -1;
	char *username = NULL;
	uint8_t *buf;

	buf = calloc(1, 65536);
	if (buf == NULL)
		return result;

	size = ident_reverse_lookup_msg_init(PACKET_TEXT(buf), isk);
	packet_lock(state, buf, size);
	safe_write(fd, buf, PACKET_BUF_SIZE(size));
	crypto_wipe(buf, PACKET_BUF_SIZE(size));

	nread = safe_read(fd, buf, 65536);
	if (nread < PACKET_BUF_SIZE(0))
		errg(fail, "Received a message that is too small.");

	if (packet_unlock(state, buf, nread))
		errg(fail, "Message cannot be decrypted.");

	{
		struct ident_reverse_lookup_reply_msg *msg = (struct ident_reverse_lookup_reply_msg *)PACKET_TEXT(buf);
		if (PACKET_TEXT_SIZE(nread) < IDENT_REVERSE_LOOKUP_REP_BASE_SIZE)
			errg(fail, "Identity reverse lookup reply message (%lu) is too small (%lu).",
				PACKET_TEXT_SIZE(nread), IDENT_REVERSE_LOOKUP_REP_BASE_SIZE);
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_REVERSE_LOOKUP_REP)
			errg(fail, "Identity lookup reply message has invalid proto or msgtype (%d, %d).",
				msg->msg.proto, msg->msg.type);
		if (PACKET_TEXT_SIZE(nread) < IDENT_REVERSE_LOOKUP_REP_SIZE(msg->username_len))
			errg(fail, "Identity reverse lookup reply message (%lu) is too small (%lu).",
				PACKET_TEXT_SIZE(nread), IDENT_REVERSE_LOOKUP_REP_SIZE(msg->username_len));

		username = malloc(msg->username_len + 1);
		if (!username)
			errg(fail, "Could not allocate memory.");

		memcpy(username, msg->username, msg->username_len);
		username[msg->username_len] = 0;
		result = 0;
	}

fail:
	crypto_wipe(buf, nread);

	*username_storage = username;
	return result;
}

int
bob(int argc, char **argv)
{
	int fd;
	const char *host, *port;
	struct packet_state state = {0};
	struct ident_state ident = {0};
	struct p2pstate *p2ptable = NULL;
	uint8_t buf[65536] = {0};
	size_t nread;

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	generate_sig_keypair(ident.isk, ident.isk_prv);
	crypto_from_eddsa_public(ident.ik,      ident.isk);
	crypto_from_eddsa_private(ident.ik_prv, ident.isk_prv);

	fd = setclientup(host, port);
	if (fd == -1)
		exit(EXIT_FAILURE);

	packet_hshake_cprepare(&state, isks, iks, ident.isk, ident.isk_prv, ident.ik, ident.ik_prv);
	packet_hshake_chello(&state, buf);
	safe_write(fd, buf, PACKET_HELLO_SIZE);
	crypto_wipe(buf, PACKET_HELLO_SIZE);

	nread = safe_read(fd, buf, PACKET_REPLY_SIZE + 1);
	if (nread != PACKET_REPLY_SIZE)
		errg(fail, "Received invalid REPLY from server.");
	if (packet_hshake_cfinish(&state, buf))
		errg(fail, "REPLY message cannot be decrypted.");
	crypto_wipe(buf, PACKET_REPLY_SIZE);

	if (register_identity(&state, &ident, fd, buf, "bob"))
		errg(fail, "Cannot register username bob");

	interactive(&ident, &state, &p2ptable, fd, buf);
	fprintf(stderr, "interactive done.\n");

fail:
	crypto_wipe(buf, 65536);
	exit(EXIT_FAILURE);
}

static
void
handle_input(struct packet_state *state, struct p2pstate *p2pstate,
		int fd, uint8_t *buf)
{
	uint8_t text[258] = {0};
	uint16_t text_size;
	size_t size;

	fscanf(stdin, "%256[^\n]", text);
	getchar();

	fprintf(stderr, "\033[F\b<%s>   %s\n",
		strcmp(p2pstate->username, "bob") == 0 ? "alice" : "bob",
		text);

	text_size = strlen((char*)(text)) + 1;

	size = send_message(state, &p2pstate->state, p2pstate->key.data, buf, text, text_size);
	safe_write(fd, buf, PACKET_BUF_SIZE(size));
	crypto_wipe(buf, PACKET_BUF_SIZE(size));
}

static
int
try_unlock_raw_message(struct packet_state *p2pstate,
		struct msg_fetch_content_msg *content,
		const char **text, size_t *text_size)
{

	if (!packet_unlock(p2pstate, content->text, load16_le(content->len))) {
		*text = (const char *)(2 + PACKET_TEXT(content->text));
		*text_size = load16_le(PACKET_TEXT(content->text));
		return 0;
	}

	*text = NULL;
	*text_size = 0;
	return -1;
}

static
int
try_unlock_prefixed_message(struct packet_state *p2pstate,
		struct msg_fetch_content_msg *content,
		const char **text, size_t *text_size)
{
	if (!packet_unlock(p2pstate,
			content->text + PACKET_P2PHELLO_SIZE(0),
			load16_le(content->len) - PACKET_P2PHELLO_SIZE(0))) {
		*text = (const char *)(2 + PACKET_TEXT(content->text + PACKET_P2PHELLO_SIZE(0)));
		*text_size = load16_le(PACKET_TEXT(content->text + PACKET_P2PHELLO_SIZE(0)));
		return 0;
	}

	*text = NULL;
	*text_size = 0;
	return -1;
}

static
int
try_unlock_hshake_message(struct ident_state *ident, struct packet_state *p2pstate,
		struct msg_fetch_content_msg *content,
		const char **text, size_t *text_size)
{
	struct hshake_ohello_msg *hmsg = (struct hshake_ohello_msg *)content->text;
	uint8_t ika[32], hk[32];
	uint8_t opk[32] = {0}, opk_prv[32] = {0};
	uint16_t innermsgsize;
	struct key key;
	struct keypair *popk, *spk;

	crypto_from_eddsa_public(ika, content->isk);
	simple_key_exchange(hk, ident->ik_prv, ika, ika, ident->ik);

	if (crypto_unlock(
			&hmsg->msgtype,
			hk,
			hmsg->nonce,
			hmsg->mac,
			&hmsg->msgtype,
			sizeof(struct hshake_ohello_msg) - offsetof(struct hshake_ohello_msg, msgtype)))
		errg(fail, "Initial message header cannot be decrypted.");

	crypto_wipe(hk, 32);

	innermsgsize = load16_le(hmsg->message_size);

	memcpy(key.data, hmsg->spkb, 32);
	spk = stbds_hmgetp_null(ident->spks, key);
	if (spk == NULL)
		errg(fail, "Message was sent with an unrecognised signed prekey.");

	if (crypto_verify32(hmsg->opkb, zero_key)) {
		memcpy(key.data, hmsg->opkb, 32);
		popk = stbds_hmgetp_null(ident->opks, key);
		if (popk == NULL)
			errg(fail, "Message was sent with an unrecognised one-time prekey.");
		memcpy(opk,     popk->key.data, 32);
		memcpy(opk_prv, popk->prv,      32);
	}

	packet_hshake_bprepare(p2pstate,
		ika, hmsg->eka,
		ident->ik, ident->ik_prv,
		spk->key.data, spk->prv,
		opk, opk_prv);

	crypto_wipe(ika,     32);
	crypto_wipe(opk,     32);
	crypto_wipe(opk_prv, 32);

	innermsgsize = padme_enc(innermsgsize + PACKET_P2PHELLO_SIZE(0)) - PACKET_P2PHELLO_SIZE(0);
	if (packet_hshake_bfinish(p2pstate, hmsg->message, innermsgsize))
		errg(fail, "Failed to decrypt of inner length %lu.", innermsgsize);

	assert(stbds_hmdel(ident->opks, key));
	crypto_wipe(&key, sizeof key);

	*text = (const char *)(2 + PACKET_TEXT(hmsg->message));
	*text_size = load16_le(PACKET_TEXT(hmsg->message));
	return 0;

fail:
	crypto_wipe(&key, sizeof key);
	crypto_wipe(hk, 32);
	crypto_wipe(ika, 32);
	crypto_wipe(opk, 32);
	crypto_wipe(opk_prv, 32);
	*text = NULL;
	*text_size = 0;
	return -1;
}

static
int
handle_message(struct ident_state *ident, struct packet_state *state,
		struct p2pstate **p2ptable, int fd, uint8_t *buf)
{
	struct msg_fetch_reply_msg *msg = (struct msg_fetch_reply_msg *)PACKET_TEXT(buf);
	size_t len = load16_le(msg->msg.len);
	size_t total_size = MSG_FETCH_REP_BASE_SIZE;
	uint8_t *message = msg->messages;
	int i, result = -1;

	if (len < MSG_FETCH_REP_BASE_SIZE)
		errg(fail, "Message fetch reply message (%lu) is too small (%lu).",
			load16_le(msg->msg.len), MSG_FETCH_REP_BASE_SIZE);

	if (msg->message_count > 1)
		errg(fail, "Message fetch replies with more than one message not yet supported (%d).",
			msg->message_count);

	if (msg->message_count == 0)
		return 0;

	if (len < MSG_FETCH_REP_SIZE(34))
		errg(fail, "Message fetch reply message (%lu) is too small (%lu).",
			load16_le(msg->msg.len), MSG_FETCH_REP_SIZE(34));

	for (i = 0; i < msg->message_count; i++) {
		struct msg_fetch_content_msg *content = (struct msg_fetch_content_msg *)message;
		struct key key;
		struct p2pstate *p2pstate;
		char message_icon = ' ';
		const char *text;
		size_t text_size;

		if (len < total_size + MSG_FETCH_CONTENT_BASE_SIZE)
			errg(fail, "Message fetch reply message (%lu) is too small (%lu).",
				len, total_size + MSG_FETCH_CONTENT_BASE_SIZE);

		if (len < total_size + MSG_FETCH_CONTENT_SIZE(load16_le(content->len)))
			errg(fail, "Message fetch reply message (%lu) is too small (%lu).",
				len, total_size + MSG_FETCH_CONTENT_SIZE(load16_le(content->len)));

		memcpy(key.data, content->isk, 32);
		p2pstate = stbds_hmgetp_null(*p2ptable, key);

		if (!p2pstate) {
			struct p2pstate newpeer = {0};
			memcpy(newpeer.key.data, key.data, 32);
			if (get_username(&newpeer.username, state, fd, key.data))
				goto fail;
			stbds_hmputs(*p2ptable, newpeer);
			p2pstate = &(*p2ptable)[stbds_hmlen(*p2ptable) - 1];
		}

		if (!try_unlock_raw_message(&p2pstate->state, content, &text, &text_size)) {
			message_icon = ' ';
			goto done;
		}

		if (!try_unlock_prefixed_message(&p2pstate->state, content, &text, &text_size)) {
			message_icon = '!';
			goto done;
		}

		if (!try_unlock_hshake_message(ident, &p2pstate->state, content, &text, &text_size)) {
			message_icon = '~';
			goto done;
		}

		fprintf(stderr, "handle_message: Failed to decrypt!\n");
		goto fail;

	done:
		fprintf(stderr, "<%s> %c %.*s\n", p2pstate->username, message_icon, (int)text_size, text);
		total_size += MSG_FETCH_CONTENT_SIZE(load16_le(content->len));
		message += MSG_FETCH_CONTENT_SIZE(load16_le(content->len));
	}

	result = 0;
fail:
	crypto_wipe(buf, 65536);
	return result;
}

static
void
handle_packet(struct ident_state *ident, struct packet_state *state,
		struct p2pstate **p2ptable, int fd, uint8_t *buf)
{
	size_t nread;

	while ((nread = safe_read_nonblock(fd, buf, 65536))) {
		struct msg *msg = (struct msg *)PACKET_TEXT(buf);

		if (nread < PACKET_BUF_SIZE(sizeof(struct msg)))
			errg(loop_continue, "handle_packet: Received a packet that is too small to be valid.");

		if (packet_unlock(state, buf, nread))
			errg(loop_continue, "handle_packet: Message cannot be decrypted.\n");

		if (PACKET_TEXT_SIZE(nread) < load16_le(msg->len))
			errg(loop_continue, "handle_packet: Received an improperly formed packet (invalid length (%lu < %lu)).\n",
				PACKET_TEXT_SIZE(nread), load16_le(msg->len));

		switch (msg->proto) {
		case PROTO_MSG:
			switch (msg->type) {
			case MSG_IMMEDIATE:
			case MSG_FETCH_REP:
				if (handle_message(ident, state, p2ptable, fd, buf))
					goto loop_fail;
				goto loop_continue;
			case MSG_FORWARD_ACK:
				goto loop_continue;
			default:
				goto loop_invalid;
			}
			break;
		case PROTO_IDENT:
			switch (msg->type) {
			default:
				goto loop_invalid;
			}
			break;
		default:
			goto loop_invalid;
		}
	loop_invalid:
		errg(loop_continue, "handle_packet: Message from server has invalid type or protocol (%d, %d).\n",
			msg->proto, msg->type);
	loop_fail:
		errg(loop_continue, "handle_packet: Unspecified error.\n");
	loop_continue:
		crypto_wipe(buf, nread);
	}
}

void
interactive(struct ident_state *ident, struct packet_state *state, struct p2pstate **p2ptable, int fd, uint8_t buf[65536])
{
	struct timespec fivesec = {5};
	int timerfd;
	struct pollfd pfds[] = {
		{STDIN_FILENO, POLLIN},
		{fd, POLLIN},
		{0, POLLIN},
	};

	pfds[2].fd = timerfd = timerfd_open(fivesec);
	if (timerfd == -1)
		err(EXIT_FAILURE, "timerfd_open");

	while (1) {
		int pcount = poll(pfds, 2, 5000);
		if (pcount == -1)
			err(EXIT_FAILURE, "poll");

		if (pcount == 0) {
			size_t size = msg_fetch_init(buf);
			packet_lock(state, buf, size);
			safe_write(fd, buf, PACKET_BUF_SIZE(size));
			crypto_wipe(buf, PACKET_BUF_SIZE(size));
			continue;
		}

		if (pfds[0].revents & (POLLERR|POLLHUP|POLLNVAL))
			err(EXIT_FAILURE, "poll");
		if (pfds[1].revents & (POLLERR|POLLHUP|POLLNVAL))
			err(EXIT_FAILURE, "poll");
		if (pfds[0].revents & POLLIN)
			handle_input(state, *p2ptable, fd, buf);
		if (pfds[1].revents & POLLIN)
			handle_packet(ident, state, p2ptable, fd, buf);
	}
}

int
register_identity(struct packet_state *state, struct ident_state *ident,
		int fd, uint8_t buf[65536], const char *name)
{
	size_t size;
	int pcount;
	unsigned regn_state = 0;
	struct pollfd pfds[1] = {{fd, POLLIN}};

	while (regn_state < 3) {
		/* fprintf(stderr, "regn_state: %u\n", regn_state); */
		if (regn_state == 0)
			size = ident_register_msg_init(ident, PACKET_TEXT(buf), name);
		else if (regn_state == 1)
			size = ident_spksub_msg_init(ident, PACKET_TEXT(buf));
		else
			size = ident_opkssub_msg_init(ident, PACKET_TEXT(buf));

		packet_lock(state, buf, size);
		safe_write(fd, buf, PACKET_BUF_SIZE(size));
		crypto_wipe(buf, PACKET_BUF_SIZE(size));
		fprintf(stderr, "sent %lu-byte (%lu-byte) %s message\n",
			size, PACKET_BUF_SIZE(size),
			regn_state == 0 ? "reg" : regn_state == 1 ? "spksub" : "opkssub");

		pcount = poll(pfds, 1, 1000);

		/* no response within timeout: repeat request */
		if (!pcount)
			continue;

		if (handle_ident_replies(fd, buf, state, 1))
			return -1;

		regn_state++;
	}

	return 0;
}
