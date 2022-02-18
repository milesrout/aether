#include <assert.h>
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

#include "hkdf.h"
#include "util.h"
#include "mesg.h"
#include "peertable.h"
#include "proof.h"
#include "ident.h"
#include "io.h"
#include "main.h"

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

static
uint8_t zero_key[32] = {0};

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

struct p2pstate {
	struct key key;
	struct mesg_state state;
};

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
	/* int opkcount; */
	/* uint8_t namelen; */

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
	if (fd == -1)
		exit(EXIT_FAILURE);

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

	memset(&p2pstate, 0, sizeof p2pstate);

	while (1) {
		struct ident_fetch_reply_msg *msg = (struct ident_fetch_reply_msg *)MESG_TEXT(buf);
		uint16_t msgsize;

		/* sleep(1); */

		*MESG_TEXT(buf) = IDENT_FETCH_MSG;
		mesg_lock(&state, buf, 1LU);
		safe_write(fd, buf, MESG_BUF_SIZE(1LU));
		crypto_wipe(buf, MESG_BUF_SIZE(1LU));

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
			/* fprintf(stderr, "No messages fetched.\n"); */
			sleep(1);
			continue;
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

		{
			uint8_t *message = msg->messages + 34;
			/* try to decrypt as a normal message */
			if (!mesg_unlock(&p2pstate, message, msgsize)) {
				fprintf(stderr, "message size: %lu\n", MESG_TEXT_SIZE(msgsize));
				displaykey("message", MESG_TEXT(message), MESG_TEXT_SIZE(msgsize));
				fprintf(stderr, "%.*s\n", (int)MESG_TEXT_SIZE(msgsize), MESG_TEXT(message));
				continue;
			}
			/* fprintf(stderr, "Failed to decrypt as message of length %lu\n", msgsize); */

		}

		{
			uint8_t *message = msg->messages + 34 + MESG_P2PHELLO_SIZE(0);
			size_t message_size = msgsize - MESG_P2PHELLO_SIZE(0);
			/* try to decrypt as a duplicate-initial message
			 * (normal messaged prefixed with OHELLO) */
			if (!mesg_unlock(&p2pstate, message, message_size)) {
				fprintf(stderr, "message size: %lu\n", MESG_TEXT_SIZE(message_size));
				displaykey("message", MESG_TEXT(message), MESG_TEXT_SIZE(message_size));
				fprintf(stderr, "%.*s\n", (int)MESG_TEXT_SIZE(message_size), MESG_TEXT(message));
				continue;
			}
			/* fprintf(stderr, "Failed to decrypt as a duplicate-initial message of length %lu\n", message_size); */
		}

		/* try to decrypt as an initial message
		 * (normal messaged prefixed with OHELLO) */
		{
			struct hshake_ohello_msg *hmsg = (struct hshake_ohello_msg *)(msg->messages + 34);
			uint8_t ika[32], hk[32];
			uint8_t opk[32] = {0}, opk_prv[32] = {0};
			uint16_t innermsgsize;
			struct key key;
			struct keypair *popk, *spk;

			crypto_from_eddsa_public(ika, msg->messages + 2);
			simple_key_exchange(hk, ident.ik_prv, ika, ika, ident.ik);

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

			innermsgsize = load16_le(hmsg->message_size);

			memcpy(key.data, hmsg->spkb, 32);
			spk = stbds_hmgetp_null(ident.spks, key);
			if (spk == NULL) {
				fprintf(stderr, "Message was sent with an unrecognised signed prekey.\n");
				goto fail;
			}

			if (crypto_verify32(hmsg->opkb, zero_key)) {
				memcpy(key.data, hmsg->opkb, 32);
				popk = stbds_hmgetp_null(ident.opks, key);
				if (popk == NULL) {
					fprintf(stderr, "Message was sent with an unrecognised one-time prekey.\n");
					goto fail;
				}
				memcpy(opk,     popk->key.data, 32);
				memcpy(opk_prv, popk->prv,      32);
			}

			mesg_hshake_bprepare(&p2pstate,
				ika, hmsg->eka,
				ident.ik, ident.ik_prv,
				spk->key.data, spk->prv,
				opk, opk_prv);

			crypto_wipe(opk,     32);
			crypto_wipe(opk_prv, 32);

			if (mesg_hshake_bfinish(&p2pstate, hmsg->message, innermsgsize)) {
				fprintf(stderr, "Failed to decrypt.\n");
				goto fail;
			}

			{
				int delresult = stbds_hmdel(ident.opks, key);
				displaykey_short("key", key.data, 32);
				fprintf(stderr, "%d\n", delresult);
				assert(delresult);
			}
			crypto_wipe(&key, sizeof key);

			fprintf(stderr, "message size: %lu\n", innermsgsize);
			displaykey("message text", MESG_TEXT(hmsg->message), innermsgsize);
			fprintf(stderr, "%.*s\n", innermsgsize, MESG_TEXT(hmsg->message));
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

