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
#include <err.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "monocypher.h"
#include "optparse.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

#include "err.h"
#include "fibre.h"
#include "queue.h"
#include "packet.h"
#include "msg.h"
#include "ident.h"
#include "chat.h"
#include "main.h"
#include "util.h"
#include "io.h"
#include "isks.h"
#include "persist.h"
#include "lockedbuf.h"

extern char *__progname;

int
prompt_line(char **buf, size_t *len, size_t *size, const char *prompt)
{
	ssize_t slen;

	printf("%s: ", prompt);
	fflush(stdout);
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
	uint32_t opk_count, spk_count, name_len, p2p_count;
	size_t left = 0uL, size = 0uL;
	const uint8_t *cur;
	struct keypair kp;
	int result = -1;
	uint8_t *keys;
	char *name;
	unsigned i;

	if (persist_read(&keys, &size, filename, password, password_len))
		goto fail;

	left = size;
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

	if (persist_load32_le(&name_len, &cur, &left)) goto fail;
	name = malloc(name_len + 1);
	if (!name) free(name);
	if (persist_loadbytes(name, name_len, &cur, &left)) goto fail;
	name[name_len] = '\0';
	ident->username = name;

	if (persist_load32_le(&p2p_count, &cur, &left)) goto fail;
	for (i = 0u; i < p2p_count; i++) {
		struct packetkey_bucket *bucket;
		uint32_t skipcount;
		struct p2pstate p2pobj, *p2p;
		uint8_t prerecv;
		uint8_t *name;
		unsigned j;

		if (persist_loadbytes(&prerecv, 1, &cur, &left)) goto fail;
		p2pobj.state.ra.rac.prerecv = prerecv;

		if (persist_loadbytes(p2pobj.key.data, 32, &cur, &left)) goto fail;
		stbds_hmputs((*p2ptable), p2pobj);
		p2p = &(*p2ptable)[i];

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

		if (persist_load32_le(&skipcount, &cur, &left)) goto fail;

		SLIST_INIT(&p2p->state.ra.rac.spare_buckets);
		SLIST_INIT(&p2p->state.ra.rac.spare_packetkeys);
		SLIST_INIT(&p2p->state.ra.rac.skipped);

		if (skipcount) {
			bucket = bucket_create(NULL);
			assert(bucket);
			SLIST_INSERT_HEAD(&p2p->state.ra.rac.skipped, bucket, buckets);

			for (j = 0u; j < skipcount; j++) {
				struct packetkey *packetkey;
				uint32_t bucketlen;
				unsigned k;

				if (persist_loadbytes(bucket->hk, 32, &cur, &left)) goto fail;
				if (persist_load32_le(&bucketlen,     &cur, &left)) goto fail;

				if (bucketlen) {
					packetkey = packetkey_create(NULL);
					assert(packetkey);
					SLIST_INSERT_HEAD(&bucket->bucket, packetkey, bucket);

					for (k = 0u; k < bucketlen; k++) {

						if (persist_load32_le(&packetkey->msn,     &cur, &left)) goto fail;
						if (persist_loadbytes(packetkey->mk,   32, &cur, &left)) goto fail;

						if (k != bucketlen - 1) {
							struct packetkey *next_packetkey = packetkey_create(NULL);
							assert(next_packetkey);
							SLIST_INSERT_AFTER(packetkey, next_packetkey, bucket);
							packetkey = next_packetkey;
						}
					}
				}

				if (j != skipcount - 1) {
					struct packetkey_bucket *next_bucket = bucket_create(NULL);
					assert(next_bucket);
					SLIST_INSERT_AFTER(bucket, next_bucket, buckets);
					bucket = next_bucket;
				}
			}
		}

		if (persist_loadstr(&name, NULL, &cur, &left)) goto fail;
		p2p->username = name;
	}

	result = 0;

fail:
	return result;
}

extern 
int
store_keys(const char *filename, const char *password, size_t password_len,
		const struct ident_state *ident,
		struct p2pstate *p2ptable);

int
store_keys(const char *filename, const char *password, size_t password_len,
		const struct ident_state *ident,
		struct p2pstate *p2ptable)
{
	size_t size = 0, left = 0;
	uint8_t *buf = NULL, *cur = NULL;
	uint32_t opk_count = 0u, spk_count = 0u, p2p_count = 0u, name_len = 0u;
	int result = -1;
	unsigned i;

	opk_count = stbds_hmlenu(ident->opks);
	spk_count = stbds_hmlenu(ident->spks);
	p2p_count = stbds_hmlenu(p2ptable);

	/* 3300 should be enough - but if it isn't, it can grow */
	size = 2200;
loop:	size += (size / 2);
	left = size;

	cur = buf = realloc(buf, size);
	assert(buf);

	if (persist_storebytes(ident->isk,     32, &cur, &left)) goto fail;
	if (persist_storebytes(ident->isk_prv, 32, &cur, &left)) goto fail;
	if (persist_storebytes(ident->ik,      32, &cur, &left)) goto fail;
	if (persist_storebytes(ident->ik_prv,  32, &cur, &left)) goto fail;

	if (persist_store32_le(opk_count, &cur, &left)) goto fail;
	for (i = 0u; i < opk_count; i++) {
		if (persist_storebytes(ident->opks[i].key.data, 32, &cur, &left)) goto fail;
		if (persist_storebytes(ident->opks[i].prv,      32, &cur, &left)) goto fail;
	}

	if (persist_store32_le(spk_count, &cur, &left)) goto fail;
	for (i = 0u; i < spk_count; i++) {
		if (persist_storebytes(ident->spks[i].key.data, 32, &cur, &left)) goto fail;
		if (persist_storebytes(ident->spks[i].prv,      32, &cur, &left)) goto fail;
		if (persist_storebytes(ident->spks[i].sig,      64, &cur, &left)) goto fail;
	}

	if (ident->username == NULL) {
		if (persist_store32_le(name_len, &cur, &left)) goto fail;
	} else {
		name_len = strlen(ident->username);
		if (persist_store32_le(name_len, &cur, &left)) goto fail;
		if (persist_storebytes(ident->username, name_len, &cur, &left)) goto fail;
	}

	if (persist_store32_le(p2p_count, &cur, &left)) goto fail;
	for (i = 0u; i < p2p_count; i++) {
		uint32_t namelen = strlen(p2ptable[i].username);
		uint8_t prerecv = p2ptable[i].state.ra.rac.prerecv ? 1 : 0;
		uint8_t *pskipcount;
		uint32_t skipcount = 0;
		struct packetkey_bucket *bucket;

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
		if (persist_store32_le(p2ptable[i].state.ra.rac.ns,           &cur, &left)) goto fail;
		if (persist_store32_le(p2ptable[i].state.ra.rac.nr,           &cur, &left)) goto fail;
		if (persist_store32_le(p2ptable[i].state.ra.rac.pn,           &cur, &left)) goto fail;
		if (prerecv) {
			if (persist_storebytes(p2ptable[i].state.rap.hk,   32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.ika,  32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.eka,  32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.spkb, 32, &cur, &left)) goto fail;
			if (persist_storebytes(p2ptable[i].state.rap.opkb, 32, &cur, &left)) goto fail;
		}

		/* initially set this to zero, then go back and correct it
		 * later once we know the correct value */
		pskipcount = cur;
		if (persist_store32_le(skipcount, &cur, &left)) goto fail;

		bucket = SLIST_FIRST(&p2ptable[i].state.ra.rac.skipped);
		while (bucket != NULL) {
			struct packetkey *packetkey;
			uint8_t *pbucketlen;
			uint32_t bucketlen = 0;

			skipcount++;

			if (persist_storebytes(bucket->hk, 32, &cur, &left)) goto fail;
			/* initially set this to zero, then go back and correct
			 * it later once we know the correct value */
			pbucketlen = cur;
			if (persist_store32_le(bucketlen,     &cur, &left)) goto fail;

			packetkey = SLIST_FIRST(&bucket->bucket);
			while (packetkey != NULL) {
				bucketlen++;

				if (persist_store32_le(packetkey->msn,     &cur, &left)) goto fail;
				if (persist_storebytes(packetkey->mk,  32, &cur, &left)) goto fail;

				packetkey = SLIST_NEXT(packetkey, bucket);
			}
			store32_le(pbucketlen, bucketlen);

			bucket = SLIST_NEXT(bucket, buckets);
		}
		store32_le(pskipcount, skipcount);

		if (persist_storestr(p2ptable[i].username, namelen, &cur, &left)) goto fail;
	}

	if (persist_write(filename, buf, size, password, password_len))
		goto end;

	result = 0;
	goto end;

fail:
	/* free(buf); */
	goto loop;

end:
	if (buf) free(buf);
	return result;
}

int save_on_quit;

__attribute__((noreturn))
static
void
usage_A(const char *errmsg, int ret)
{
	if (errmsg)
		fprintf(stderr, "%s: %s:", __progname, errmsg);
	fprintf(stderr, "usage: %s -B [-b HOST] [-p PORT]\n", __progname);
	exit(ret);
}

int
alice_old(char **argv, int subopt)
{
	int fd;
	uint8_t ikb[32], spkb[32], opkb[32];
	uint8_t spkb_sig[64];
	union packet_state state;
	struct p2pstate *p2ptable = NULL;
	struct p2pstate *p2pstate;
	struct p2pstate bobstate = {0};
	struct ident_state *ident;
	const char *host, *port;
	uint8_t buf[BUFSZ] = {0};
	size_t bufsz = BUFSZ;
	char *username = NULL, *password = NULL, *peername = NULL;
	size_t nread, size;
	size_t username_len, username_size;
	size_t password_len, password_size;
	size_t peername_len, peername_size;
	const char *error;
	struct optparse options;
	int option;
	char mode;

	optparse_init(&options, argv - 1);
	options.permute = 0;
	options.subopt = subopt;

	host = "127.0.0.1";
	port = "3443";
	mode = 'n';

	while ((option = optparse(&options, "onhb:p:")) != -1) switch (option) {
		case 'o': mode = 'o'; break;
		case 'n': mode = 'n'; break;
		case 'b': host = options.optarg; break;
		case 'p': port = options.optarg; break;
		case 'h': usage_A(NULL, 0);
		default:  usage(options.errmsg, 1);
	}

	save_on_quit = 1;
	fibre_init(CLIENT_STACK_SIZE);

	ident = lockedbuf(NULL, sizeof(struct ident_state));

	/* load or generate keys */
	if (prompt_line(&password, &password_len, &password_size, "Password"))
		errx(1, "Could not read password");

	if (mode == 'n') {
		generate_sig_keypair(ident->isk, ident->isk_prv);
		crypto_from_eddsa_public(ident->ik, ident->isk);
		crypto_from_eddsa_private(ident->ik_prv, ident->isk_prv);
	} else {
		if (load_keys(ident, &p2ptable, "alice.keys", password, password_len))
			errx(1, "Could not load keys from file `%s'", "alice.keys");
	}

	/* set up networking */
	fd = setclientup(host, port);
	if (fd == -1)
		err(1, "setclientup");

	/* send HELLO message */
	packet_hshake_cprepare(&state, isks, iks,
		ident->isk, ident->isk_prv,
		ident->ik, ident->ik_prv,
		NULL);
	packet_hshake_chello(&state, buf);
	safe_write(fd, buf, PACKET_HELLO_SIZE);
	crypto_wipe(buf, PACKET_HELLO_SIZE);

	/* recv REPLY message */
	error = safe_read(&nread, fd, buf, PACKET_REPLY_SIZE + 1);
	if (error)
		errx(1, "%s", error);
	if (nread < PACKET_REPLY_SIZE)
		errx(1, "Received invalid reply from server");
	if (packet_hshake_cfinish(&state, buf))
		errx(1, "Reply message cannot be decrypted");
	crypto_wipe(buf, PACKET_REPLY_SIZE);

	/* REGISTER username/SPKSUB/OPKSSUB keys */
	if (mode != 'n')
		goto skip_new_stuff;

	if (prompt_line(&username, &username_len, &username_size, "Username"))
		errx(1, "Could not read username");

	if (register_identity(ident, &state, fd, buf, bufsz, username))
		errx(1, "Cannot register username %s", username);

	if (store_keys("alice.keys", password, password_len, ident, p2ptable))
		errx(1, "Could not store keys in file `%s'", "alice.keys");

	/* send LOOKUP */
	if (prompt_line(&peername, &peername_len, &peername_size, "Peername"))
		errx(1, "Could not read peer's name");

	bobstate.username = peername;
	size = ident_lookup_msg_init(PACKET_TEXT(buf), PACKET_TEXT_SIZE(bufsz), peername);
	packet_lock(&state, buf, size);
	safe_write(fd, buf, PACKET_BUF_SIZE(size));
	crypto_wipe(buf, PACKET_BUF_SIZE(size));

	/* recv LOOKUP reply */
	error = safe_read(&nread, fd, buf, bufsz);
	if (error)
		errx(1, "%s", error);
	if (nread < PACKET_BUF_SIZE(0))
		errx(1, "Received a message that is too small");
	if (packet_unlock(&state, buf, nread))
		errx(1, "Lookup message cannot be decrypted");

	{
		struct ident_lookup_reply_msg *msg = (struct ident_lookup_reply_msg *)(PACKET_TEXT(buf) + 12);
		if (PACKET_TEXT_SIZE(nread) < sizeof *msg)
			errx(1, "Identity lookup reply message (%lu) is too small (%lu)",
				PACKET_TEXT_SIZE(nread), sizeof *msg);
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_LOOKUP_REP)
			errx(1, "Identity lookup reply message has invalid proto or msgtype (%d, %d)",
				msg->msg.proto, msg->msg.type);

		memcpy(bobstate.key.data, msg->isk, 32);
		stbds_hmputs(p2ptable, bobstate);
		p2pstate = &p2ptable[stbds_hmlen(p2ptable) - 1];
	}

	/* send KEYREQ */
	size = ident_keyreq_msg_init(ident, PACKET_TEXT(buf), PACKET_TEXT_SIZE(bufsz), p2pstate->key.data);
	{
		uint8_t *p = PACKET_TEXT(buf) + size;
		size_t s = size;
		if (persist_zeropad(padme_enc(size) - size, &p, &s))
			errx(1, "total shambles");
	}
	packet_lock(&state, buf, padme_enc(size));
	safe_write(fd, buf, padme(PACKET_BUF_SIZE(size)));
	crypto_wipe(buf, padme(PACKET_BUF_SIZE(size)));

	/* recv KEYREQ reply */
	error = safe_read(&nread, fd, buf, bufsz);
	if (error)
		errx(1, "%s", error);
	if (nread < PACKET_BUF_SIZE(0))
		errx(1, "Received a message that is too small");
	if (packet_unlock(&state, buf, nread))
		errx(1, "Keyreq message cannot be decrypted");

	{
		struct ident_keyreq_reply_msg *msg = (struct ident_keyreq_reply_msg *)(PACKET_TEXT(buf) + 12);
		if (PACKET_TEXT_SIZE(nread) < sizeof *msg)
			errx(1, "Key bundle request reply message (%lu) is too small (%lu)",
				PACKET_TEXT_SIZE(nread), sizeof *msg);
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_KEYREQ_REP)
			errx(1, "Key bundle request reply message has invalid proto or msgtype (%d, %d)",
				msg->msg.proto, msg->msg.type);

		crypto_from_eddsa_public(ikb, p2pstate->key.data);
		memcpy(spkb,     msg->spk,     32);
		memcpy(spkb_sig, msg->spk_sig, 64);
		memcpy(opkb,     msg->opk,     32);

		crypto_wipe(buf, nread);
	}

	/* Peer-to-peer HELLO */
	if (packet_hshake_aprepare(&p2pstate->state, ident->ik, ident->ik_prv,
			p2pstate->key.data, ikb, spkb, spkb_sig, opkb))
		errx(1, "Error preparing handshake");

skip_new_stuff:
	/* Send and receive messages */
	interactive(ident, &state, &p2ptable, fd);

	exit(0);
}


int
alice(char **argv, int subopt)
{
	char       *username = NULL, *password = NULL, *peername = NULL, *desc = NULL;
	size_t      username_size, password_size, peername_size, descsize;
	size_t      username_len, password_len, peername_len, desclen;
	struct      p2pstate *p2ptable = NULL;
	struct      msg_state state = {0};
	const char *host, *port, *error;
	struct      ident_state *ident;
	uint8_t     buf[BUFSZ] = {0};
	struct      optparse options;
	int         r, fd, option;
	size_t      len, nread;
	char        mode;

	STAILQ_INIT(&state.eventq);
	STAILQ_INIT(&state.sendq);

	optparse_init(&options, argv - 1);
	options.permute = 0;
	options.subopt = subopt;

	host = "127.0.0.1";
	port = "3443";
	mode = 'n';

	while ((option = optparse(&options, "onhb:p:")) != -1) switch (option) {
		case 'o': mode = 'o'; break;
		case 'n': mode = 'n'; break;
		case 'b': host = options.optarg; break;
		case 'p': port = options.optarg; break;
		case 'h': usage_A(NULL, 0);
		default:  usage(options.errmsg, 1);
	}

	save_on_quit = 1;
	fibre_init(CLIENT_STACK_SIZE);

	ident = lockedbuf(NULL, sizeof(struct ident_state));

	/* load or generate keys */
	if (prompt_line(&password, &password_len, &password_size, "Password"))
		errx(1, "Could not read password");

	if (mode == 'n') {
		generate_sig_keypair(ident->isk, ident->isk_prv);
		crypto_from_eddsa_public(ident->ik, ident->isk);
		crypto_from_eddsa_private(ident->ik_prv, ident->isk_prv);
	} else {
		if (load_keys(ident, &p2ptable, "alice.keys", password, password_len))
			errx(1, "Could not load keys from file `%s'", "alice.keys");
	}

	/* set up networking */
	fd = setclientup(host, port);
	if (fd == -1)
		err(1, "setclientup");
	packet_hshake_cprepare(&state.ps, isks, iks,
		ident->isk, ident->isk_prv,
		ident->ik, ident->ik_prv,
		NULL);
	packet_hshake_chello(&state.ps, buf);
	safe_write(fd, buf, PACKET_HELLO_SIZE);
	crypto_wipe(buf, PACKET_HELLO_SIZE);

	/* recv REPLY message */
	error = safe_read(&nread, fd, buf, PACKET_REPLY_SIZE + 1);
	if (error)
		errx(1, "safe_read: %s", error);
	if (nread < PACKET_REPLY_SIZE)
		errx(1, "Received invalid reply from server");
	if (packet_hshake_cfinish(&state.ps, buf))
		errx(1, "Reply message cannot be decrypted");

	crypto_wipe(buf, PACKET_REPLY_SIZE);

	for (;;) {
		struct msg_event *ev = NULL;

		/* depending on the state, we need to send a message here, in
		 * order to prompt the server into DOING something */

		error = safe_read(&nread, fd, buf, BUFSZ);
		if (error)
			errx(1, "%s", error);
		if (nread < PACKET_BUF_SIZE(0))
			errx(1, "Received message that is too small");

		r = msg_recv(&state, buf, nread);
		if (r) errx(1, "Could not decrypt message");

		while (msg_next_event(&state, &ev)) {
			fprintf(stderr, "Received %zu-byte %s/%s (id=%lu)\n",
				ev->len, msg_proto(ev->proto),
				msg_type(ev->proto, ev->type), ev->id);
		}

		while (msg_send(&state, buf, BUFSZ, &len, &desc, &descsize, &desclen)) {
			error = safe_write(fd, buf, len);
			if (error)
				errx(1, "safe_write: %s", error);
			printf("-> %zu\t%.*s\n", len, (int)desclen, desc);
			desclen = 0;
			*desc = 0;
		}
	}
}
