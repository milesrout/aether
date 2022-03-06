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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <time.h>

#include "monocypher.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

#include "err.h"
#include "packet.h"
#include "msg.h"
#include "ident.h"
#include "messaging.h"
#include "main.h"
#include "util.h"
#include "io.h"
#include "isks.h"
#include "persist.h"

int
prompt_line(char **buf, size_t *len, size_t *size, const char *prompt)
{
	ssize_t slen;

	printf("%s: ", prompt);
	if ((slen = getline(buf, size, stdin)) == -1L)
		return -1;

	*len = (size_t)slen;

	assert((*buf)[*len] == '\0');
	assert((*buf)[*len - 1] == '\n');
	(*buf)[*len - 1] = '\0';
	(*len)--;

	return 0;
}

static
int
load_keys(struct ident_state *ident, struct p2pstate **p2ptable,
		const char *filename, const char *password, size_t password_len)
{
	uint32_t opk_count, spk_count, p2p_count;
	size_t left = 0uL, size = 0uL;
	uint8_t *keys;
	const uint8_t *cur;
	struct keypair kp;
	unsigned i;

	if (persist_read(&keys, &left, filename, password, password_len)) {
		warnx("persist_read");
		goto fail;
	}

	size = left;
	cur = keys;
	ident->opks = ident->spks = NULL;
	*p2ptable = NULL;

	if (persist_loadbytes(ident->isk,     32, &cur, &left)) goto fail;
	if (persist_loadbytes(ident->isk_prv, 32, &cur, &left)) goto fail;
	if (persist_loadbytes(ident->ik,      32, &cur, &left)) goto fail;
	if (persist_loadbytes(ident->ik_prv,  32, &cur, &left)) goto fail;

	if (persist_load32_le(&opk_count, &cur, &left)) goto fail;
	for (i = 0u; i < opk_count; i++) {
		if (persist_loadbytes(kp.key.data, 32, &cur, &left)) goto fail;
		if (persist_loadbytes(kp.prv,      32, &cur, &left)) goto fail;
		stbds_hmputs(ident->opks, kp);
	}

	if (persist_load32_le(&spk_count, &cur, &left)) goto fail;
	for (i = 0u; i < spk_count; i++) {
		if (persist_loadbytes(kp.key.data, 32, &cur, &left)) goto fail;
		if (persist_loadbytes(kp.prv,      32, &cur, &left)) goto fail;
		if (persist_loadbytes(kp.sig,      64, &cur, &left)) goto fail;
		stbds_hmputs(ident->spks, kp);
	}

	if (persist_load32_le(&p2p_count, &cur, &left)) goto fail;
	for (i = 0u; i < p2p_count; i++) {
		uint8_t prerecv;
		struct p2pstate *p2p;
		uint32_t namelen;
		uint8_t *name;

		stbds_hmputs((*p2ptable), (struct p2pstate){0});
		p2p = &(*p2ptable)[i];

		if (persist_loadbytes(&prerecv, 1, &cur, &left)) goto fail;
		p2p->state.ra.rac.prerecv = prerecv;

		if (prerecv)
			left += 32 * 5;

		if (persist_loadbytes(p2p->key.data,              32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.dhkr,     32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.dhks,     32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.dhks_prv, 32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.rk,       32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.cks,      32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.ckr,      32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.hks,      32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.hkr,      32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.nhks,     32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.nhkr,     32, &cur, &left)) goto fail;
		if (persist_loadbytes(p2p->state.ra.rac.ad,       64, &cur, &left)) goto fail;
		if (persist_load32_le(&p2p->state.ra.rac.ns,          &cur, &left)) goto fail;
		if (persist_load32_le(&p2p->state.ra.rac.nr,          &cur, &left)) goto fail;
		if (persist_load32_le(&p2p->state.ra.rac.pn,          &cur, &left)) goto fail;
		if (prerecv) {
			if (persist_loadbytes(p2p->state.rap.hk,   32, &cur, &left)) goto fail;
			if (persist_loadbytes(p2p->state.rap.ika,  32, &cur, &left)) goto fail;
			if (persist_loadbytes(p2p->state.rap.eka,  32, &cur, &left)) goto fail;
			if (persist_loadbytes(p2p->state.rap.spkb, 32, &cur, &left)) goto fail;
			if (persist_loadbytes(p2p->state.rap.opkb, 32, &cur, &left)) goto fail;
		}
		if (persist_load32_le(&namelen, &cur, &left)) goto fail;
		name = malloc(namelen + 1);
		if (persist_loadbytes(name, namelen, &cur, &left)) goto fail;
		name[namelen] = 0;
		p2p->username = (const char *)name;
	}

	return 0;
fail:
	fprintf(stderr, "%p %p %lu %lu\n", keys, cur, size, left);
	return -1;
}

static
int
store_keys(const char *filename, const char *password, size_t password_len,
		const struct ident_state *ident,
		struct p2pstate *p2ptable)
{
	size_t size, left;
	uint8_t *buf = NULL, *cur;
	uint32_t opk_count = 0u, spk_count = 0u, p2p_count = 0u;
	int result = -1;
	unsigned i;

	opk_count = stbds_hmlenu(ident->opks);
	spk_count = stbds_hmlenu(ident->spks);
	p2p_count = stbds_hmlenu(p2ptable);

	left = size = 128
		+ 4 + opk_count * (32 + 32)
		+ 4 + spk_count * (32 + 32 + 64)
		+ 4 + p2p_count * (32 + (1 + (32 * 10) + 64 + 4 * 3) + 4);

	buf = malloc(size);
	if (buf == NULL)
		errg(fail, "malloc");
	cur = buf;

	if (persist_storebytes(ident->isk,     32, &cur, &left)) goto fail;
	if (persist_storebytes(ident->isk_prv, 32, &cur, &left)) goto fail;
	if (persist_storebytes(ident->ik,      32, &cur, &left)) goto fail;
	if (persist_storebytes(ident->ik_prv,  32, &cur, &left)) goto fail;

	if (persist_store32_le(&opk_count,         &cur, &left)) goto fail;
	for (i = 0u; i < opk_count; i++) {
		if (persist_storebytes(ident->opks[i].key.data, 32, &cur, &left)) goto fail;
		if (persist_storebytes(ident->opks[i].prv,      32, &cur, &left)) goto fail;
	}

	if (persist_store32_le(&spk_count, &cur, &left)) goto fail;
	for (i = 0u; i < spk_count; i++) {
		if (persist_storebytes(ident->spks[i].key.data, 32, &cur, &left)) goto fail;
		if (persist_storebytes(ident->spks[i].prv,      32, &cur, &left)) goto fail;
		if (persist_storebytes(ident->spks[i].sig,      64, &cur, &left)) goto fail;
	}

	if (persist_store32_le(&p2p_count, &cur, &left)) goto fail;
	for (i = 0u; i < p2p_count; i++) {
		uint32_t namelen = strlen(p2ptable[i].username);
		uint8_t prerecv = p2ptable[i].state.ra.rac.prerecv ? 1 : 0;

		left += namelen;
		if (prerecv)
			left += 32 * 5;

		if (persist_storebytes(&prerecv, 1, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].key.data,              32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.dhkr,     32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.dhks,     32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.dhks_prv, 32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.rk,       32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.cks,      32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.ckr,      32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.hks,      32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.hkr,      32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.nhks,     32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.nhkr,     32, &cur, &left)) goto fail;
		if (persist_storebytes(p2ptable[i].state.ra.rac.ad,       64, &cur, &left)) goto fail;
		if (persist_store32_le(&p2ptable[i].state.ra.rac.ns,          &cur, &left)) goto fail;
		if (persist_store32_le(&p2ptable[i].state.ra.rac.nr,          &cur, &left)) goto fail;
		if (persist_store32_le(&p2ptable[i].state.ra.rac.pn,          &cur, &left)) goto fail;
		if (prerecv) {
			if (persist_storebytes(p2ptable[i].state.rap.hk,   32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.ika,  32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.eka,  32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.spkb, 32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.opkb, 32, &cur, &left)) goto fail;
		}
		if (persist_store32_le(&namelen, &cur, &left)) goto fail;
		if (persist_storebytes((const uint8_t *)p2ptable[i].username, namelen, &cur, &left)) goto fail;
	}

	if (persist_write(filename, buf, size, password, password_len))
		goto fail;

	result = 0;
fail:
	fprintf(stderr, "%p %p %lu %lu\n", buf, cur, size, left);
	if (buf) free(buf);
	return result;
}

int
alice(int argc, char **argv)
{
	int fd;
	uint8_t ikb[32], spkb[32], opkb[32];
	uint8_t spkb_sig[64];
	union packet_state state;
	struct p2pstate *p2ptable = NULL;
	struct p2pstate *p2pstate;
	struct p2pstate bobstate = {0};
	struct ident_state ident = {0};
	const char *host, *port, *mode;
	uint8_t buf[65536] = {0};
	char *username = NULL, *password = NULL;
	size_t nread, size;
	size_t username_len, username_size;
	size_t password_len, password_size;

	/* argument handling */
	if (argc < 2 || argc > 5)
		usage();

	mode = argc < 3? "new" : argv[2];
	host = argc < 4? "127.0.0.1" : argv[3];
	port = argc < 5? "3443" : argv[4];

	/* load or generate keys */
	if (prompt_line(&password, &password_len, &password_size, "Password"))
		errx(EXIT_FAILURE, "Could not read password");

	if (mode[0] == 'n') {
		generate_sig_keypair(ident.isk, ident.isk_prv);
		crypto_from_eddsa_public(ident.ik, ident.isk);
		crypto_from_eddsa_private(ident.ik_prv, ident.isk_prv);
	} else {
		if (load_keys(&ident, &p2ptable, "keys.enc", password, password_len))
			errx(EXIT_FAILURE, "Could not load keys from file `%s'", "keys.enc");
	}

	/* set up networking */
	fd = setclientup(host, port);
	if (fd == -1)
		err(EXIT_FAILURE, "setclientup");

	/* send HELLO message */
	packet_hshake_cprepare(&state, isks, iks,
		ident.isk, ident.isk_prv,
		ident.ik, ident.ik_prv,
		NULL);
	packet_hshake_chello(&state, buf);
	safe_write(fd, buf, PACKET_HELLO_SIZE);
	crypto_wipe(buf, PACKET_HELLO_SIZE);

	/* recv REPLY message */
	nread = safe_read(fd, buf, PACKET_REPLY_SIZE + 1);
	if (nread < PACKET_REPLY_SIZE)
		err(EXIT_FAILURE, "Received invalid reply from server");
	if (packet_hshake_cfinish(&state, buf))
		err(EXIT_FAILURE, "Reply message cannot be decrypted");
	crypto_wipe(buf, PACKET_REPLY_SIZE);

	/* REGISTER username/SPKSUB/OPKSSUB keys */
	if (mode[0] == 'n') {
		if (prompt_line(&username, &username_len, &username_size, "Username"))
			err(EXIT_FAILURE, "Could not read username");

		if (register_identity(&ident, &state, fd, buf, username))
			err(EXIT_FAILURE, "Cannot register username %s", username);

		if (store_keys("keys.enc", password, password_len, &ident, p2ptable))
			errx(EXIT_FAILURE, "Could not store keys in file `%s'", "keys.enc");
	}

	/* send LOOKUP */
	bobstate.username = "bob";
	size = ident_lookup_msg_init(PACKET_TEXT(buf), "bob");
	packet_lock(&state, buf, size);
	safe_write(fd, buf, PACKET_BUF_SIZE(size));
	crypto_wipe(buf, PACKET_BUF_SIZE(size));

	/* recv LOOKUP reply */
	nread = safe_read(fd, buf, 65536);
	if (nread < PACKET_BUF_SIZE(0))
		err(EXIT_FAILURE, "Received a message that is too small");
	if (packet_unlock(&state, buf, nread))
		err(EXIT_FAILURE, "Lookup message cannot be decrypted");

	{
		struct ident_lookup_reply_msg *msg = (struct ident_lookup_reply_msg *)PACKET_TEXT(buf);
		if (PACKET_TEXT_SIZE(nread) < sizeof *msg)
			err(EXIT_FAILURE, "Identity lookup reply message (%lu) is too small (%lu)",
				PACKET_TEXT_SIZE(nread), sizeof *msg);
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_LOOKUP_REP)
			err(EXIT_FAILURE, "Identity lookup reply message has invalid proto or msgtype (%d, %d)",
				msg->msg.proto, msg->msg.type);

		memcpy(bobstate.key.data, msg->isk, 32);
		stbds_hmputs(p2ptable, bobstate);
		p2pstate = &p2ptable[stbds_hmlen(p2ptable) - 1];
	}

	/* send KEYREQ */
	size = ident_keyreq_msg_init(&ident, PACKET_TEXT(buf), p2pstate->key.data);
	packet_lock(&state, buf, size);
	safe_write(fd, buf, PACKET_BUF_SIZE(size));
	crypto_wipe(buf, PACKET_BUF_SIZE(size));

	/* recv KEYREQ reply */
	nread = safe_read(fd, buf, 65536);
	if (nread < PACKET_BUF_SIZE(0))
		err(EXIT_FAILURE, "Received a message that is too small");
	if (packet_unlock(&state, buf, nread))
		err(EXIT_FAILURE, "Keyreq message cannot be decrypted");

	{
		struct ident_keyreq_reply_msg *msg = (struct ident_keyreq_reply_msg *)PACKET_TEXT(buf);
		if (PACKET_TEXT_SIZE(nread) < sizeof *msg)
			err(EXIT_FAILURE, "Key bundle request reply message (%lu) is too small (%lu)",
				PACKET_TEXT_SIZE(nread), sizeof *msg);
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_KEYREQ_REP)
			err(EXIT_FAILURE, "Key bundle request reply message has invalid proto or msgtype (%d, %d)",
				msg->msg.proto, msg->msg.type);

		crypto_from_eddsa_public(ikb, p2pstate->key.data);
		memcpy(spkb,     msg->spk,     32);
		memcpy(spkb_sig, msg->spk_sig, 64);
		memcpy(opkb,     msg->opk,     32);

		crypto_wipe(buf, nread);
	}

	/* Peer-to-peer HELLO */
	if (packet_hshake_aprepare(&p2pstate->state, ident.ik, ident.ik_prv,
			p2pstate->key.data, ikb, spkb, spkb_sig, opkb))
		err(EXIT_FAILURE, "Error preparing handshake");

	/* Send and receive messages */
	interactive(&ident, &state, &p2ptable, fd, username);

	exit(EXIT_SUCCESS);
}

