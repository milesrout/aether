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
	const char *host, *port;
	uint8_t buf[65536] = {0};
	char *username = NULL;
	size_t nread, size, username_len;
	ssize_t iread;

	/* argument handling */
	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	/* generate keys */
	generate_sig_keypair(ident.isk, ident.isk_prv);
	crypto_from_eddsa_public(ident.ik, ident.isk);
	crypto_from_eddsa_private(ident.ik_prv, ident.isk_prv);

	/* set up networking */
	fd = setclientup(host, port);
	if (fd == -1)
		err(EXIT_FAILURE, "setclientup");

	/* send HELLO message */
	packet_hshake_cprepare(&state, isks, iks,
		ident.isk, ident.isk_prv,
		ident.ik, ident.ik_prv);
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

	/* REGISTER username */
	printf("Username: ");
	if ((iread = getline(&username, &username_len, stdin)) == -1)
		err(EXIT_FAILURE, "Could not read username");

	assert(username[iread - 1] == '\n');
	assert(username[iread] == '\0');
	username[iread - 1] = '\0';

	/* randusername(username, "alice"); */
	if (register_identity(&ident, &state, fd, buf, username))
		err(EXIT_FAILURE, "Cannot register username %s", username);

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

