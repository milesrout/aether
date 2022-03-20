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
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
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
#include "timer.h"
#include "fibre.h"

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

static
uint8_t zero_key[32] = {0};

static
const char *
send_packet(union packet_state *state, int fd, uint8_t *buf, size_t size)
{
	const char *error;

	packet_lock(state, buf, size);
	error = safe_write(fd, buf, PACKET_BUF_SIZE(size));
	crypto_wipe(buf, PACKET_BUF_SIZE(size));

	return error;
}

static
int
handle_ident_replies(union packet_state *state, int fd, uint8_t buf[BUFSZ])
{
	uint8_t *text = PACKET_TEXT(buf);
	size_t nread, size;
	const char *error;

	error = safe_read(&nread, fd, buf, BUFSZ);
	if (error)
		errg(fail, "handle_ident_replies: Failed to read from socket: %s", error);

	size = PACKET_TEXT_SIZE(nread);
	if (nread < PACKET_BUF_SIZE(0))
		errg(fail, "handle_ident_replies: Received a message that is too small");

	if (packet_unlock(state, buf, nread))
		errg(fail, "handle_ident_replies: Message cannot be decrypted");

	if (size >= 1) {
		struct msg *msg = (struct msg *)text;

		if (msg->proto != PROTO_IDENT)
			errg(fail, "handle_ident_replies: Message is not an identity-related message");

		switch (msg->type) {
		case IDENT_OPKSSUB_ACK: {
			struct ident_opkssub_ack_msg *msg = (void *)text;
			if (size < sizeof *msg)
				errg(fail, "OPKs submission ack message is the wrong size");
			fprintf(stderr, "OPKs submission ack\n");
			if (msg->result)
				goto fail;
			break;
		}
		case IDENT_SPKSUB_ACK: {
			struct ident_spksub_ack_msg *msg = (void *)text;
			if (size < sizeof *msg)
				errg(fail, "SPK submission ack message is the wrong size");
			fprintf(stderr, "SPK submission ack\n");
			if (msg->result)
				goto fail;
			break;
		}
		case IDENT_REGISTER_ACK: {
			struct ident_register_ack_msg *msg = (void *)text;
			if (size < sizeof *msg)
				errg(fail, "Registration ack message is the wrong size");
			fprintf(stderr, "Registration submission ack\n");
			if (msg->result)
				goto fail;
			break;
		}
		default:
			fprintf(stderr, "handle_ident_replies: Unrecognised message type %d\n", text[0]);
			fprintf(stderr, "(proto,type,len) = (%d,%d,%d)\n",
				msg->proto, msg->type, load16_le(msg->len));
			displaykey("buf (decrypted)", buf, nread);
			displaykey("text", text, size);
			goto fail;
		}
	}

	return 0;
fail:
	crypto_wipe(buf, BUFSZ);
	return -1;
}


/* USERNAMES */

static
int
get_username(const char **username_storage, union packet_state *state, int fd, uint8_t isk[32])
{
	char *username = NULL;
	size_t size, nread;
	const char *error;
	int result = -1;
	uint8_t buf[1024];
	size_t bufsz = 1024;

	size = ident_reverse_lookup_msg_init(PACKET_TEXT(buf), PACKET_TEXT_SIZE(bufsz), isk);
	error = send_packet(state, fd, buf, size);
	if (error)
		errg(fail, "Failed to send packet: %s", error);

	fibre_awaitfd(fd, EPOLLIN);
	error = safe_read(&nread, fd, buf, bufsz);
	if (error)
		errg(fail, "Failed to read from socket: %s", error);

	if (nread < PACKET_BUF_SIZE(0))
		errg(fail, "Received a message that is too small");

	if (packet_unlock(state, buf, nread))
		errg(fail, "Message cannot be decrypted");

	{
		struct ident_reverse_lookup_reply_msg *msg = (struct ident_reverse_lookup_reply_msg *)PACKET_TEXT(buf);
		if (PACKET_TEXT_SIZE(nread) < IDENT_REVERSE_LOOKUP_REP_BASE_SIZE)
			errg(fail, "Identity reverse lookup reply message (%lu) is too small (%lu)",
				PACKET_TEXT_SIZE(nread), IDENT_REVERSE_LOOKUP_REP_BASE_SIZE);
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_REVERSE_LOOKUP_REP)
			errg(fail, "Identity lookup reply message has invalid proto or msgtype (%d, %d)",
				msg->msg.proto, msg->msg.type);
		if (PACKET_TEXT_SIZE(nread) < IDENT_REVERSE_LOOKUP_REP_SIZE(msg->username_len))
			errg(fail, "Identity reverse lookup reply message (%lu) is too small (%lu)",
				PACKET_TEXT_SIZE(nread), IDENT_REVERSE_LOOKUP_REP_SIZE(msg->username_len));

		username = malloc(msg->username_len + 1);
		if (!username)
			errg(fail, "Could not allocate memory");

		memcpy(username, msg->username, msg->username_len);
		username[msg->username_len] = 0;
		result = 0;
	}

fail:
	crypto_wipe(buf, nread);

	*username_storage = username;
	return result;
}

extern int save_on_quit;

static
void
handle_input(union packet_state *state, struct p2pstate **p2ptable,
		int fd, uint8_t *buf, size_t bufsz, const char *username)
{
	struct p2pstate *p2pstate;
	uint8_t text[258] = {0};
	uint16_t text_size;
	const char *error;
	size_t size;
	ssize_t ssize;
	int n;

	n = fscanf(stdin, "%256[^\n]", text);
	while (n == EOF && ferror(stdin) && errno == EAGAIN) {
		fibre_awaitfd(STDIN_FILENO, EPOLLIN);
		n = fscanf(stdin, "%256[^\n]", text);
	}

	getchar();

	text_size = strlen((char*)(text)) + 1;

	if (text[0] == '/') {
		if (strcmp((const char *)text, "/quit") == 0) {
			ssize = chat_goodbye_init(PACKET_TEXT(buf),
				PACKET_TEXT_SIZE(bufsz), NULL);
			if (ssize == -1)
				errx(1, "Failed to create GOODBYE");
			size = (size_t)ssize;
			error = send_packet(state, fd, buf, size);
			if (error)
				errx(1, "Failed to send GOODBYE: %s", error);
		} else {
			printf("Unknown command: %s\n", text);
		}
		return;
	}

	/* just grab the first item of the table if it exists
	 * this is dreadfully unsafe, but works fine if alice speaks first
	 */
	p2pstate = *p2ptable;

	fprintf(stderr, "\033[F\b<%s> %s\n", username, text);
	size = send_message(state, &p2pstate->state,
		p2pstate->key.data, buf, bufsz, text, text_size);
	error = safe_write(fd, buf, PACKET_BUF_SIZE(size));
	crypto_wipe(buf, PACKET_BUF_SIZE(size));
	if (error)
		errx(1, "Failed to send message: %s", error);
}

static
int
try_unlock_raw_message(union packet_state *p2pstate,
		struct chat_fetch_content_msg *content,
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
try_unlock_prefixed_message(union packet_state *p2pstate,
		struct chat_fetch_content_msg *content,
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
try_unlock_hshake_message(struct ident_state *ident, union packet_state *p2pstate,
		struct chat_fetch_content_msg *content,
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
		errg(fail, "Initial message header cannot be decrypted");

	crypto_wipe(hk, 32);

	innermsgsize = load16_le(hmsg->message_size);

	memcpy(key.data, hmsg->spkb, 32);
	spk = stbds_hmgetp_null(ident->spks, key);
	if (spk == NULL)
		errg(fail, "Message was sent with an unrecognised signed prekey");

	if (crypto_verify32(hmsg->opkb, zero_key)) {
		memcpy(key.data, hmsg->opkb, 32);
		popk = stbds_hmgetp_null(ident->opks, key);
		if (popk == NULL)
			errg(fail, "Message was sent with an unrecognised one-time prekey");
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
		errg(fail, "Failed to decrypt of inner length %lu", innermsgsize);

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
handle_message(struct ident_state *ident, union packet_state *state,
		struct p2pstate **p2ptable, int fd, uint8_t *buf)
{
	struct chat_fetch_reply_msg *msg = (struct chat_fetch_reply_msg *)PACKET_TEXT(buf);
	size_t len = load16_le(msg->msg.len);
	size_t total_size = CHAT_FETCH_REP_BASE_SIZE;
	uint8_t *message = msg->messages;
	int i, result = -1;

	if (len < CHAT_FETCH_REP_BASE_SIZE)
		errg(fail, "Message fetch reply message (%lu) is too small (%lu)",
			load16_le(msg->msg.len), CHAT_FETCH_REP_BASE_SIZE);

	if (msg->message_count > 1)
		errg(fail, "Message fetch replies with more than one message not yet supported (%d)",
			msg->message_count);

	if (msg->message_count == 0)
		return 0;

	if (len < CHAT_FETCH_REP_SIZE(34))
		errg(fail, "Message fetch reply message (%lu) is too small (%lu)",
			load16_le(msg->msg.len), CHAT_FETCH_REP_SIZE(34));

	for (i = 0; i < msg->message_count; i++) {
		struct chat_fetch_content_msg *content = (struct chat_fetch_content_msg *)message;
		struct key key;
		struct p2pstate *p2pstate;
		const char *text;
		size_t text_size;

		if (len < total_size + CHAT_FETCH_CONTENT_BASE_SIZE)
			errg(fail, "Message fetch reply message (%lu) is too small (%lu)",
				len, total_size + CHAT_FETCH_CONTENT_BASE_SIZE);

		if (len < total_size + CHAT_FETCH_CONTENT_SIZE(load16_le(content->len)))
			errg(fail, "Message fetch reply message (%lu) is too small (%lu)",
				len, total_size + CHAT_FETCH_CONTENT_SIZE(load16_le(content->len)));

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

		if (!try_unlock_raw_message(&p2pstate->state, content, &text, &text_size))
			goto done;

		if (!try_unlock_prefixed_message(&p2pstate->state, content, &text, &text_size))
			goto done;

		if (!try_unlock_hshake_message(ident, &p2pstate->state, content, &text, &text_size))
			goto done;

		fprintf(stderr, "handle_message: Failed to decrypt!\n");
		goto fail;

	done:
		fprintf(stderr, "<%s> %.*s\n", p2pstate->username, (int)text_size, text);
		total_size += CHAT_FETCH_CONTENT_SIZE(load16_le(content->len));
		message += CHAT_FETCH_CONTENT_SIZE(load16_le(content->len));
	}

	result = 0;
fail:
	crypto_wipe(buf, BUFSZ);
	return result;
}

extern
int
store_keys(const char *filename, const char *password, size_t password_len,
		const struct ident_state *ident,
		struct p2pstate *p2ptable);

static
void
handle_packet(struct ident_state *ident, union packet_state *state,
		struct p2pstate **p2ptable, int fd, uint8_t *buf, size_t bufsz)
{
	const char *error;
	struct msg *msg;
	size_t nread;
	
	for (;;) {
		error = safe_read(&nread, fd, buf, bufsz);
		if (error)
			errg(loop_continue, "handle_packet: Could not read from socket: %s", error);
		msg = (struct msg *)PACKET_TEXT(buf);

		if (nread < PACKET_BUF_SIZE(sizeof(struct msg)))
			errg(loop_continue, "handle_packet: Received a packet that is too small to be valid");

		if (packet_unlock(state, buf, nread))
			errg(loop_continue, "handle_packet: Message cannot be decrypted");

		if (PACKET_TEXT_SIZE(nread) < load16_le(msg->len))
			errg(loop_continue, "handle_packet: Received an improperly formed packet (invalid length (%lu < %lu))",
				PACKET_TEXT_SIZE(nread), load16_le(msg->len));

		switch (msg->proto) {
		case PROTO_CHAT:
			switch (msg->type) {
			case CHAT_IMMEDIATE:
			case CHAT_FETCH_REP:
				if (handle_message(ident, state, p2ptable, fd, buf))
					goto loop_fail;
				goto loop_continue;
			case CHAT_FORWARD_ACK:
				goto loop_continue;
			case CHAT_GOODBYE_ACK:
				goto loop_quit;
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
		errg(loop_continue, "handle_packet: Message from server has invalid type or protocol (%d, %d)",
			msg->proto, msg->type);
	loop_fail:
		errg(loop_continue, "handle_packet: Unspecified error");
	loop_quit:
		if (save_on_quit)
			store_keys("alice.keys", "alice", strlen("alice"), ident, *p2ptable);
		exit(0);
	loop_continue:
		crypto_wipe(buf, nread);
	}
}

struct client_ctx {
	struct ident_state *ident;
	union packet_state *state;
	struct p2pstate **p2ptable;
};

static
void
fetch_thread(long fd_long, void *ctx_void)
{
	struct client_ctx *ctx = ctx_void;
	int fd = fd_long;
	struct timespec ts = {15};
	uint64_t expirations;
	uint8_t buf[1024];
	size_t bufsz = 1024;
	const char *error;
	int timerfd;
	ssize_t n, size;

	timerfd = timerfd_open(ts);
	if (timerfd == -1)
		err(1, "timerfd_open");

	for (;;) {
		do n = fibre_read(timerfd, &expirations, sizeof expirations);
		while (n == -1 && errno == EINTR);
		if (n == -1)
			warn("Could not read timer expirations");

		size = chat_fetch_init(PACKET_TEXT(buf), PACKET_TEXT_SIZE(bufsz));
		if (size == -1)
			err(1, "Could not create FETCH message");
		packet_lock(ctx->state, buf, size);
		error = safe_write(fd, buf, PACKET_BUF_SIZE(size));
		crypto_wipe(buf, PACKET_BUF_SIZE(size));
		if (error)
			warnx("Could not send FETCH message: %s", error);
	}
}

static
void
input_thread(long fd_long, void *ctx_void)
{
	struct client_ctx *ctx = ctx_void;
	int fd = fd_long;
	uint8_t buf[BUFSZ];
	size_t bufsz = BUFSZ;

	fcntl_nonblock(STDIN_FILENO);

	for (;;) {
		handle_input(ctx->state, ctx->p2ptable, fd, buf, bufsz,
			ctx->ident->username);
	}
}

static
void
handler_thread(long fd_long, void *ctx_void)
{
	struct client_ctx *ctx = ctx_void;
	int fd = fd_long;
	uint8_t buf[BUFSZ] = {0};
	size_t bufsz = BUFSZ;

	for (;;) {
		handle_packet(ctx->ident, ctx->state, ctx->p2ptable, fd, buf, bufsz);
	}
}

void
interactive(struct ident_state *ident, union packet_state *state,
		struct p2pstate **p2ptable, int fd)
{
	int dupfd1, dupfd2;
	struct client_ctx ctx = {ident, state, p2ptable};

	dupfd1 = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd1 == -1)
		err(1, "fcntl(F_DUPFD_CLOEXEC)");

	dupfd2 = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd2 == -1)
		err(1, "fcntl(F_DUPFD_CLOEXEC)");

	fibre_go(FP_BACKGROUND, fetch_thread, fd, &ctx);
	fibre_go(FP_NORMAL, input_thread, dupfd1, &ctx);
	fibre_go(FP_NORMAL, handler_thread, dupfd2, &ctx);

	fibre_return();
}

int
register_identity(struct ident_state *ident, union packet_state *state,
		int fd, uint8_t *buf, size_t bufsz, const char *name)
{
	struct pollfd pfds[1] = {{fd, POLLIN}};
	unsigned regn_state = 0;
	const char *error;
	size_t size;
	int pcount;

	ident->username = name;

	while (regn_state < 3) {
		if (regn_state == 0)
			size = ident_register_msg_init(ident, PACKET_TEXT(buf), PACKET_TEXT_SIZE(bufsz), name);
		else if (regn_state == 1)
			size = ident_spksub_msg_init(ident, PACKET_TEXT(buf), PACKET_TEXT_SIZE(bufsz));
		else
			size = ident_opkssub_msg_init(ident, PACKET_TEXT(buf), PACKET_TEXT_SIZE(bufsz));

		packet_lock(state, buf, size);
		error = safe_write(fd, buf, PACKET_BUF_SIZE(size));
		if (error) {
			fprintf(stderr, "register_identity: safe_write: %s\n", error);
			return -1;
		}
		crypto_wipe(buf, PACKET_BUF_SIZE(size));
		fprintf(stderr, "sent %lu-byte (%lu-byte) %s message\n",
			size, PACKET_BUF_SIZE(size),
			regn_state == 0 ? "reg" : regn_state == 1 ? "spksub" : "opkssub");

		pcount = poll(pfds, 1, 1000);

		/* no response within timeout: repeat request */
		if (!pcount)
			continue;

		if (handle_ident_replies(state, fd, buf))
			return -1;

		regn_state++;
	}

	return 0;
}

int
bob(char **argv, int subopt)
{
	int fd;
	const char *host, *port;
	union packet_state state = {0};
	struct ident_state ident = {0};
	struct p2pstate *p2ptable = NULL;
	uint8_t buf[BUFSZ];
	size_t bufsz = BUFSZ;
	const char *error;
	size_t nread;
	struct optparse options;
	int option;

	optparse_init(&options, argv - 1);
	options.permute = 0;
	options.subopt = subopt;

	host = "127.0.0.1";
	port = "3443";

	while ((option = optparse(&options, "h:p:")) != -1) switch (option) {
		case 'h': host = options.optarg; break;
		case 'p': port = options.optarg; break;
		default:  usage(options.errmsg, 1); break;
	}


	save_on_quit = 0;
	fibre_init(CLIENT_STACK_SIZE);

	generate_sig_keypair(ident.isk, ident.isk_prv);
	crypto_from_eddsa_public(ident.ik,      ident.isk);
	crypto_from_eddsa_private(ident.ik_prv, ident.isk_prv);

	fd = setclientup(host, port);
	if (fd == -1)
		err(1, "Could not set client up");

	packet_hshake_cprepare(&state, isks, iks,
		ident.isk, ident.isk_prv,
		ident.ik, ident.ik_prv,
		NULL);
	packet_hshake_chello(&state, buf);
	safe_write(fd, buf, PACKET_HELLO_SIZE);
	crypto_wipe(buf, PACKET_HELLO_SIZE);

	error = safe_read(&nread, fd, buf, PACKET_REPLY_SIZE + 1);
	if (error)
		errx(1, "Could not read from socket: %s", error);
	if (nread != PACKET_REPLY_SIZE)
		errx(1, "Received invalid REPLY from server");
	if (packet_hshake_cfinish(&state, buf))
		errx(1, "REPLY message cannot be decrypted");
	crypto_wipe(buf, PACKET_REPLY_SIZE);

	if (register_identity(&ident, &state, fd, buf, bufsz, "bob"))
		errx(1, "Cannot register username bob");

	interactive(&ident, &state, &p2ptable, fd);

	exit(0);
}
