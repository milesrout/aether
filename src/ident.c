#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "mesg.h"
#include "monocypher.h"

#include "ident.h"

static const uint8_t zero_key[32];

void
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
			next_key += 32;
			count += 1;
		}
	}
	store16_le(msg->opk_count, count);
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

void
ident_spksub_msg_init(struct ident_state *state, uint8_t *buf)
{
	struct ident_spksub_msg *msg = (struct ident_spksub_msg *)buf;

	msg->msgtype = IDENT_SPKSUB_MSG;
	memmove(state->oldspk_prv, state->spk_prv, 32);
	generate_kex_keypair(msg->spk, state->spk_prv);
	sign_key(msg->spk_sig, state->isk_prv, state->isk, "AIBS", msg->spk);
}

void
ident_keyreq_msg_init(struct ident_state *state, uint8_t *buf, const uint8_t ik[32])
{
	struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)buf;

	msg->msgtype = IDENT_KEYREQ_MSG;
	memcpy(msg->ik, ik, 32);

	(void)state;
}
