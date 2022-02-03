#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "mesg.h"
#include "monocypher.h"

#include "ident.h"

static const uint8_t zero_key[32];

size_t
ident_opkssub_msg_init(struct ident_state *state, uint8_t *buf)
{
	struct ident_opkssub_msg *msg = (struct ident_opkssub_msg *)buf;
	uint8_t *next_key = buf + sizeof *msg;
	int count = 0;
	int i;

	msg->msgtype = IDENT_OPKSSUB_MSG;
	for (i = 0; i < 32; i++) {
		if (!crypto_verify32(state->opk_prvs[i], zero_key)) {
			generate_kex_keypair(next_key, state->opk_prvs[i]);
			displaykey("opk", next_key, 32);
			next_key += 32;
			count += 1;
		}
	}
	store16_le(msg->opk_count, count);

	return IDENT_OPKSSUB_MSG_SIZE(count);
}

size_t
ident_opkssub_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result)
{
	struct ident_opkssub_ack_msg *msg = (struct ident_opkssub_ack_msg *)buf;

	msg->msgtype = IDENT_OPKSSUB_ACK;
	memcpy(msg->msn, msn, 4);
	msg->result = result;

	return sizeof *msg;
}

size_t
ident_spksub_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result)
{
	struct ident_spksub_ack_msg *msg = (struct ident_spksub_ack_msg *)buf;

	msg->msgtype = IDENT_SPKSUB_ACK;
	memcpy(msg->msn, msn, 4);
	msg->result = result;

	return sizeof *msg;
}

size_t
ident_register_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result)
{
	struct ident_register_ack_msg *msg = (struct ident_register_ack_msg *)buf;

	msg->msgtype = IDENT_REGISTER_ACK;
	memcpy(msg->msn, msn, 4);
	msg->result = result;

	return sizeof *msg;
}

size_t
ident_register_msg_init(struct ident_state *state, uint8_t *buf, char const *username)
{
	struct ident_register_msg *msg = (struct ident_register_msg *)buf;
	uint8_t username_len = strlen(username);

	msg->msgtype = IDENT_REGISTER_MSG;
	/* generate_kex_keypair(state->ik, state->ik_prv); */
	/* memcpy(msg->ik, state->ik, 32); */
	/* sign_key(msg->ik_sig, state->isk_prv, state->isk, "AIBI", msg->ik); */
	msg->username_len = username_len;
	memcpy(msg->username, username, username_len);
	msg->username[username_len] = '\0';

	(void)state;

	return IDENT_REGISTER_MSG_SIZE(username_len);
}

size_t
ident_spksub_msg_init(struct ident_state *state, uint8_t *buf)
{
	struct ident_spksub_msg *msg = (struct ident_spksub_msg *)buf;

	msg->msgtype = IDENT_SPKSUB_MSG;
	memmove(state->oldspk_prv, state->spk_prv, 32);
	generate_kex_keypair(msg->spk, state->spk_prv);
	sign_key(msg->spk_sig, state->isk_prv, state->isk, "AIBS", msg->spk);

	return IDENT_SPKSUB_MSG_SIZE;
}

size_t
ident_lookup_msg_init(struct ident_state *state, uint8_t *buf, const char *username)
{
	struct ident_lookup_msg *msg = (struct ident_lookup_msg *)buf;
	uint8_t len = strlen(username);

	msg->msgtype = IDENT_LOOKUP_MSG;
	msg->username_len = len;
	memcpy(msg->username, username, len);
	msg->username[len] = '\0';

	(void)state;

	return IDENT_LOOKUP_MSG_SIZE(len);
}

size_t
ident_lookup_rep_init(uint8_t *buf, uint8_t msn[4], uint8_t isk[32])
{
	struct ident_lookup_reply_msg *msg = (struct ident_lookup_reply_msg *)buf;

	msg->msgtype = IDENT_LOOKUP_REP;
	memcpy(msg->msn, msn, 4);
	memcpy(msg->isk, isk, 32);

	return sizeof *msg;
}

size_t
ident_keyreq_msg_init(struct ident_state *state, uint8_t *buf, const uint8_t isk[32])
{
	struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)buf;

	msg->msgtype = IDENT_KEYREQ_MSG;
	memcpy(msg->isk, isk, 32);

	(void)state;

	return IDENT_KEYREQ_MSG_SIZE;
}

size_t
ident_keyreq_rep_init(uint8_t *buf, uint8_t msn[4],
		/* uint8_t ik[32], uint8_t ik_sig[64], */
		uint8_t spk[32], uint8_t spk_sig[64], uint8_t opk[32])
{
	struct ident_keyreq_reply_msg *msg = (struct ident_keyreq_reply_msg *)buf;

	msg->msgtype = IDENT_KEYREQ_REP;
	memcpy(msg->msn,     msn,     4);
	/* memcpy(msg->ik,      ik,      32); */
	/* memcpy(msg->ik_sig,  ik_sig,  64); */
	memcpy(msg->spk,     spk,     32);
	memcpy(msg->spk_sig, spk_sig, 64);
	memcpy(msg->opk,     opk,     32);

	return sizeof *msg;
}

size_t
ident_forward_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result)
{
	struct ident_forward_ack_msg *msg = (struct ident_forward_ack_msg *)buf;

	msg->msgtype = IDENT_FORWARD_ACK;
	memcpy(msg->msn, msn, 4);
	msg->result = result;

	return sizeof *msg;
}

size_t
ident_fetch_rep_init(uint8_t *buf, uint8_t msn[4], uint8_t msgcount)
{
	struct ident_fetch_reply_msg *msg = (struct ident_fetch_reply_msg *)buf;

	msg->msgtype = IDENT_FETCH_REP;
	memcpy(msg->msn, msn, 4);
	msg->message_count = msgcount;

	return sizeof *msg;
}


void
ident_opkssub_msg_reply(struct client_ident_state *state, struct ident_opkssub_msg *msg)
{
	int i, j, ntr, opk_count;

	opk_count = load16_le(msg->opk_count);
	if (opk_count > 8)
		opk_count = 8;

	ntr = opk_count - (8 - state->opks_valid);

	j = 0;
	for (i = 0; i < 8; i++) {
		if (!crypto_verify32(state->opks[i], zero_key) || ntr-- > 0) {
			memcpy(state->opks[i], msg->opk[j++], 32);
		}
	}
}
