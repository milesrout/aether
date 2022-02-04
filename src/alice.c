#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "monocypher.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

#include "ident.h"
#include "main.h"
#include "mesg.h"
#include "util.h"
#include "io.h"
#include "isks.h"

int
alice(int argc, char **argv)
{
	int fd;
	uint8_t iska[32], iska_prv[32];
	uint8_t ika[32], ika_prv[32];
	uint8_t iskb[32], ikb[32], spkb[32], opkb[32];
	uint8_t ikb_sig[64], spkb_sig[64];
	struct mesg_state state;
	struct mesg_state p2pstate;
	struct ident_state ident;
	const char *host, *port;
	uint8_t buf[65536];
	size_t nread, size;

	if (argc < 2 || argc > 4)
		usage();

	host = argc < 3? "127.0.0.1" : argv[2];
	port = argc < 4? "3443" : argv[3];

	generate_sig_keypair(iska, iska_prv);
	/* generate_kex_keypair(ika, ika_prv); */
	crypto_from_eddsa_public(ika,      iska);
	crypto_from_eddsa_private(ika_prv, iska_prv);

	fd = setclientup(host, port);
	if (fd == -1)
		exit(EXIT_FAILURE);

	mesg_hshake_cprepare(&state, isks, iks, iska, iska_prv, ika, ika_prv);
	mesg_hshake_chello(&state, buf);
	safe_write(fd, buf, MESG_HELLO_SIZE);
	crypto_wipe(buf, MESG_HELLO_SIZE);

	nread = safe_read(fd, buf, MESG_REPLY_SIZE + 1);
	if (nread != MESG_REPLY_SIZE) {
		fprintf(stderr, "Received invalid reply from server.\n");
		crypto_wipe(buf, MESG_REPLY_SIZE);
		return -1;
	}

	if (mesg_hshake_cfinish(&state, buf)) {
		fprintf(stderr, "Reply message cannot be decrypted.\n");
		crypto_wipe(buf, MESG_REPLY_SIZE);
		return -1;
	}

	crypto_wipe(buf, MESG_REPLY_SIZE);

	size = ident_lookup_msg_init(&ident, MESG_TEXT(buf), "bob");
	mesg_lock(&state, buf, size);
	safe_write(fd, buf, MESG_BUF_SIZE(size));
	crypto_wipe(buf, MESG_BUF_SIZE(size));
	fprintf(stderr, "sent %lu-byte (%lu-byte) lookup message\n",
		size, MESG_BUF_SIZE(size));

	nread = safe_read(fd, buf, 65536);
	if (nread < MESG_BUF_SIZE(0)) {
		fprintf(stderr, "Received a message that is too small.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf", buf, nread);
	if (mesg_unlock(&state, buf, nread)) {
		fprintf(stderr, "Message cannot be decrypted.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf (decrypted)", buf, nread);
	displaykey("text", MESG_TEXT(buf), MESG_TEXT_SIZE(nread));

	{
		struct ident_lookup_reply_msg *msg = (struct ident_lookup_reply_msg *)MESG_TEXT(buf);
		if (MESG_TEXT_SIZE(nread) != sizeof *msg) {
			fprintf(stderr, "Identity lookup reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg);
			crypto_wipe(buf, nread);
			return -1;
		}
		if (msg->msgtype != IDENT_LOOKUP_REP) {
			fprintf(stderr, "Identity lookup reply message has invalid msgtype (%d).\n",
				msg->msgtype);
			crypto_wipe(buf, nread);
			return -1;
		}

		memcpy(iskb, msg->isk, 32);
	}

	size = ident_keyreq_msg_init(&ident, MESG_TEXT(buf), iskb);
	mesg_lock(&state, buf, size);
	safe_write(fd, buf, MESG_BUF_SIZE(size));
	crypto_wipe(buf, MESG_BUF_SIZE(size));
	fprintf(stderr, "sent %lu-byte (%lu-byte) keyreq message\n",
		size, MESG_BUF_SIZE(size));

	nread = safe_read(fd, buf, 65536);
	if (nread < MESG_BUF_SIZE(0)) {
		fprintf(stderr, "Received a message that is too small.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf", buf, nread);
	if (mesg_unlock(&state, buf, nread)) {
		fprintf(stderr, "Message cannot be decrypted.\n");
		crypto_wipe(buf, nread);
		return -1;
	}
	displaykey("buf (decrypted)", buf, nread);
	displaykey("text", MESG_TEXT(buf), MESG_TEXT_SIZE(nread));

	{
		struct ident_keyreq_reply_msg *msg = (struct ident_keyreq_reply_msg *)MESG_TEXT(buf);
		if (MESG_TEXT_SIZE(nread) != sizeof *msg) {
			fprintf(stderr, "Key bundle request reply message (%lu) is too small (%lu).\n",
				MESG_TEXT_SIZE(nread), sizeof *msg);
			crypto_wipe(buf, nread);
			return -1;
		}
		if (msg->msgtype != IDENT_KEYREQ_REP) {
			fprintf(stderr, "Key bundle request reply message has invalid msgtype (%d).\n",
				msg->msgtype);
			crypto_wipe(buf, nread);
			return -1;
		}

		/* displaykey_short("ik", msg->ik, 32); */

		/* memcpy(ikb,      msg->ik,      32); */
		crypto_from_eddsa_public(ikb, iskb);
		/* memcpy(ikb_sig,  msg->ik_sig,  64); */
		memcpy(spkb,     msg->spk,     32);
		memcpy(spkb_sig, msg->spk_sig, 64);
		memcpy(opkb,     msg->opk,     32);

		displaykey_short("ikb",  ikb,  32);
		displaykey_short("spkb", spkb, 32);
		displaykey_short("opkb", opkb, 32);
		/* displaykey("ikb_sig",  ikb_sig,  64); */
		displaykey("spkb_sig", spkb_sig, 64);
	}

	crypto_wipe(buf, 65536);
	displaykey_short("ika", ika, 32);
	if (mesg_hshake_aprepare(&p2pstate, ika, ika_prv,
		iskb, ikb, /*ikb_sig,*/ spkb, spkb_sig, opkb)) {
		fprintf(stderr, "Error preparing handshake.\n");
		return -1;
	}

	{
		struct ident_forward_msg *msg = (void *)MESG_TEXT(buf);
		uint8_t *text = MESG_TEXT(buf); /* start of message to server */
		uint8_t *smsg = text + IDENT_FORWARD_MSG_BASE_SIZE + 2; /* start of encapsulated message */
		uint8_t *cbuf = smsg + MESG_P2PHELLO_SIZE(0); /* start of internal message */
		uint8_t *ctext = MESG_TEXT(cbuf);
		const uint16_t msglength = 24;

		memset(ctext, 0x77, msglength);

		store16_le(cbuf - 2, msglength);
		mesg_hshake_ahello(&p2pstate, smsg, msglength);
		msg->msgtype = IDENT_FORWARD_MSG;
		memcpy(msg->isk, iskb, 32);
		msg->message_count = 1;
		store16_le(msg->messages, MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)));
		mesg_lock(&state, buf, IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength))));
		safe_write(fd, buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
		fprintf(stderr, "sent %lu-byte (%lu-byte) lookup message\n",
			IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength))),
			MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
		crypto_wipe(buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
	}

	{
		struct ident_forward_msg *msg = (void *)MESG_TEXT(buf);
		uint8_t *text = MESG_TEXT(buf); /* start of message to server */
		uint8_t *smsg = text + IDENT_FORWARD_MSG_BASE_SIZE + 2; /* start of encapsulated message */
		uint8_t *cbuf = smsg + MESG_P2PHELLO_SIZE(0); /* start of internal message */
		uint8_t *ctext = MESG_TEXT(cbuf);
		const uint16_t msglength = 38;

		memset(ctext, 0xa5, msglength/2);
		memset(ctext + msglength/2, 0x5a, msglength/2);

		store16_le(cbuf - 2, msglength);
		mesg_hshake_ahello(&p2pstate, smsg, msglength);
		msg->msgtype = IDENT_FORWARD_MSG;
		memcpy(msg->isk, iskb, 32);
		msg->message_count = 1;
		store16_le(msg->messages, MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)));
		mesg_lock(&state, buf, IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength))));
		safe_write(fd, buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
		fprintf(stderr, "sent %lu-byte (%lu-byte) message\n",
			IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength))),
			MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
		crypto_wipe(buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
	}

	while (1) {
		struct ident_forward_msg *msg = (void *)MESG_TEXT(buf);
		uint8_t *text = MESG_TEXT(buf); /* start of message to server */
		uint8_t *smsg = text + IDENT_FORWARD_MSG_BASE_SIZE + 2; /* start of encapsulated message */
		uint8_t *cbuf = smsg + MESG_P2PHELLO_SIZE(0); /* start of internal message */
		uint8_t *ctext = MESG_TEXT(cbuf);
		uint16_t msglength;

		memset(ctext, 0, 65536 - (ctext - buf));
		fscanf(stdin, "%256[^\n]", ctext);
		getchar();
		msglength = strlen((char*)ctext);
		fprintf(stderr, "n = %d\n", msglength);
		fprintf(stderr, "s = [%.*s]\n", msglength, ctext);

		store16_le(cbuf - 2, msglength);
		mesg_hshake_ahello(&p2pstate, smsg, msglength);
		msg->msgtype = IDENT_FORWARD_MSG;
		memcpy(msg->isk, iskb, 32);
		msg->message_count = 1;
		store16_le(msg->messages, MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)));
		mesg_lock(&state, buf, IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength))));
		safe_write(fd, buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
		fprintf(stderr, "sent %lu-byte (%lu-byte) lookup message\n",
			IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength))),
			MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
		crypto_wipe(buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)))));
	}

	goto fail;

	/* { */
	/* 	struct ident_forward_msg *msg = (void *)MESG_TEXT(buf); */
	/* 	msg->msgtype = IDENT_FORWARD_MSG; */
	/* 	memcpy(msg->isk, iskb, 32); */
	/* 	msg->message_count = 1; */
	/* 	store16_le(msg->messages, MESG_P2PHELLO_SIZE(24)); */
	/* 	mesg_hshake_ahello(&p2pstate, msg->messages + 2, 24); */
	/* 	mesg_lock(&state, buf, IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24)) + 96); */
	/* 	displaykey("buf", buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24))) + 96); */
	/* 	safe_write(fd, buf, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24))) + 96); */
	/* 	fprintf(stderr, "sent %lu-byte (%lu-byte) lookup message\n", */
	/* 		IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24)) + 96, MESG_BUF_SIZE(IDENT_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(24))) + 96); */
	/* } */

	/* memset(MESG_OHELLO_TEXT(MESG_TEXT(buf)), 0x77, 24); */
	/* mesg_hshake_ahello(&p2pstate, MESG_TEXT(buf), 24); */
	/* mesg_lock(&state, buf, MESG_P2PHELLO_SIZE(24)); */
	/* safe_write(fd, buf, MESG_BUF_SIZE(MESG_P2PHELLO_SIZE(24))); */

	/* memset(MESG_TEXT(buf) + MESG_P2PHELLO_SIZE(0), 0x77, 24); */
	/* mesg_hshake_ahello(&p2pstate, MESG_TEXT(buf), 24); */
	/* safe_write(fd, buf, MESG_BUF_SIZE(MESG_P2PHELLO_SIZE(24))); */

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

		/* if ((size_t)nread > MESG_BUF_SIZE(1)) { */
		/* 	mesg_lock(&state, buf, MESG_TEXT_SIZE(nread) - 1); */
		/* 	safe_write(fd, buf, nread - 1); */
		/* 	fprintf(stderr, "sent %lu-byte (%lu-byte) message\n", MESG_TEXT_SIZE(nread) - 1, nread - 1); */
		/* } */

		/* crypto_wipe(buf, 65536); */

		/* nread = safe_read(fd, buf, 65536); */
	/* } */

	exit(EXIT_SUCCESS);
fail:
	crypto_wipe(buf, 65536);
	exit(EXIT_FAILURE);
}

