#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "monocypher.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

#include "mesg.h"
#include "msg.h"
#include "ident.h"
#include "messaging.h"
#include "main.h"
#include "util.h"
#include "io.h"
#include "isks.h"

extern int handle_ident_replies(int fd, uint8_t buf[65536],
	struct mesg_state *state, int minreplies);

int
alice(int argc, char **argv)
{
	int fd;
	/* uint8_t iska[32], iska_prv[32]; */
	/* uint8_t ika[32], ika_prv[32]; */
	uint8_t ikb[32], spkb[32], opkb[32];
	uint8_t spkb_sig[64];
	struct mesg_state state;
	/* struct p2pstate p2pstate = {0}; */
	struct p2pstate *p2ptable = NULL;
	struct p2pstate *p2pstate;
	struct p2pstate bobstate = {0};
	struct ident_state ident = {0};
	const char *host, *port;
	uint8_t buf[65536] = {0};
	char username[12] = {0};
	size_t nread, size;

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
		exit(EXIT_FAILURE);

	/* send HELLO message */
	mesg_hshake_cprepare(&state, isks, iks,
		ident.isk, ident.isk_prv,
		ident.ik, ident.ik_prv);
	mesg_hshake_chello(&state, buf);
	safe_write(fd, buf, MESG_HELLO_SIZE);
	crypto_wipe(buf, MESG_HELLO_SIZE);

	/* recv REPLY message */
	nread = safe_read(fd, buf, MESG_REPLY_SIZE + 1);
	if (nread < MESG_REPLY_SIZE) {
		fprintf(stderr, "Received invalid reply from server.\n");
		goto fail;
	}
	if (mesg_hshake_cfinish(&state, buf)) {
		fprintf(stderr, "Reply message cannot be decrypted.\n");
		goto fail;
	}
	crypto_wipe(buf, MESG_REPLY_SIZE);

	/* REGISTER username */
	randusername(username, "alice");
	if (register_identity(&state, &ident, fd, buf, username)) {
		fprintf(stderr, "Cannot register username %s\n", username);
		goto fail;
	}

	/* send LOOKUP */
	bobstate.username = "bob";
	size = ident_lookup_msg_init(MESG_TEXT(buf), "bob");
	mesg_lock(&state, buf, size);
	safe_write(fd, buf, MESG_BUF_SIZE(size));
	crypto_wipe(buf, MESG_BUF_SIZE(size));

	/* recv LOOKUP reply */
	nread = safe_read(fd, buf, 65536);
	if (nread < MESG_BUF_SIZE(0)) {
		fprintf(stderr, "Received a message that is too small.\n");
		goto fail;
	}
	if (mesg_unlock(&state, buf, nread)) {
		fprintf(stderr, "Message cannot be decrypted.\n");
		goto fail;
	}

	{
		struct ident_lookup_reply_msg *msg = (struct ident_lookup_reply_msg *)MESG_TEXT(buf);
		if (MESG_TEXT_SIZE(nread) < sizeof *msg) {
			fprintf(stderr, "Identity lookup reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg);
			goto fail;
		}
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_LOOKUP_REP) {
			fprintf(stderr, "Identity lookup reply message has invalid proto or msgtype (%d, %d).\n",
				msg->msg.proto, msg->msg.type);
			goto fail;
		}

		memcpy(bobstate.key.data, msg->isk, 32);
		stbds_hmputs(p2ptable, bobstate);
		p2pstate = &p2ptable[stbds_hmlen(p2ptable) - 1];
	}

	/* send KEYREQ */
	size = ident_keyreq_msg_init(&ident, MESG_TEXT(buf), p2pstate->key.data);
	mesg_lock(&state, buf, size);
	safe_write(fd, buf, MESG_BUF_SIZE(size));
	crypto_wipe(buf, MESG_BUF_SIZE(size));

	/* recv KEYREQ reply */
	nread = safe_read(fd, buf, 65536);
	if (nread < MESG_BUF_SIZE(0)) {
		fprintf(stderr, "Received a message that is too small.\n");
		goto fail;
	}

	if (mesg_unlock(&state, buf, nread)) {
		fprintf(stderr, "Message cannot be decrypted.\n");
		goto fail;
	}

	{
		struct ident_keyreq_reply_msg *msg = (struct ident_keyreq_reply_msg *)MESG_TEXT(buf);
		if (MESG_TEXT_SIZE(nread) < sizeof *msg) {
			fprintf(stderr, "Key bundle request reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg);
			goto fail;
		}
		if (msg->msg.proto != PROTO_IDENT || msg->msg.type != IDENT_KEYREQ_REP) {
			fprintf(stderr, "Key bundle request reply message has invalid proto or msgtype (%d, %d).\n",
				msg->msg.proto, msg->msg.type);
			goto fail;
		}

		crypto_from_eddsa_public(ikb, p2pstate->key.data);
		memcpy(spkb,     msg->spk,     32);
		memcpy(spkb_sig, msg->spk_sig, 64);
		memcpy(opkb,     msg->opk,     32);

		crypto_wipe(buf, nread);
	}

	/* Peer-to-peer HELLO */
	if (mesg_hshake_aprepare(&p2pstate->state, ident.ik, ident.ik_prv,
			p2pstate->key.data, ikb, spkb, spkb_sig, opkb)) {
		fprintf(stderr, "Error preparing handshake.\n");
		goto fail;
	}

	/* Send and receive messages */
	interactive(&ident, &state, &p2ptable, fd, buf);
	exit(EXIT_SUCCESS);
fail:
	crypto_wipe(buf, 65536);
	exit(EXIT_FAILURE);
}

