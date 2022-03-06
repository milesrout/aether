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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#define STBDS_NO_SHORT_NAMES
#include "stb_ds.h"

#include "util.h"
#include "packet.h"
#include "msg.h"
#include "ident.h"

static
int
fill_opks(struct ident_state *state, ptrdiff_t max)
{
	ptrdiff_t i, num;
	struct keypair kp = {0};

	num = stbds_hmlen(state->opks);
	for (i = 0; i < max - num; i++) {
		generate_kex_keypair(kp.key.data, kp.prv);
		stbds_hmputs(state->opks, kp);
	}

	return max - num;
}

#define MAX_OPKS 32

size_t
ident_opkssub_msg_init(struct ident_state *state, uint8_t *buf)
{
	struct ident_opkssub_msg *msg = (struct ident_opkssub_msg *)buf;
	uint8_t *next_key = buf + sizeof *msg;
	int count = 0;
	int i;

	count = fill_opks(state, MAX_OPKS);

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_OPKSSUB_MSG;
	store16_le(msg->msg.len, IDENT_OPKSSUB_MSG_SIZE(count));
	for (i = 0; i < count; i++) {
		memcpy(next_key, state->opks[MAX_OPKS - count + i].key.data, 32);
		next_key += 32;
	}
	store16_le(msg->opk_count, count);

	return padme_enc(IDENT_OPKSSUB_MSG_SIZE(count));
}

size_t
ident_opkssub_ack_init(uint8_t *buf, uint8_t result)
{
	struct ident_opkssub_ack_msg *msg = (struct ident_opkssub_ack_msg *)buf;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_OPKSSUB_ACK;
	store16_le(msg->msg.len, sizeof *msg);
	msg->result = result;

	return padme_enc(sizeof *msg);
}

size_t
ident_spksub_ack_init(uint8_t *buf, uint8_t result)
{
	struct ident_spksub_ack_msg *msg = (struct ident_spksub_ack_msg *)buf;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_SPKSUB_ACK;
	store16_le(msg->msg.len, sizeof *msg);
	msg->result = result;

	return padme_enc(sizeof *msg);
}

size_t
ident_register_ack_init(uint8_t *buf, uint8_t result)
{
	struct ident_register_ack_msg *msg = (struct ident_register_ack_msg *)buf;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_REGISTER_ACK;
	store16_le(msg->msg.len, sizeof *msg);
	msg->result = result;

	return padme_enc(sizeof *msg);
}

size_t
ident_register_msg_init(struct ident_state *state, uint8_t *buf, char const *username)
{
	struct ident_register_msg *msg = (struct ident_register_msg *)buf;
	uint8_t username_len = strlen(username);

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_REGISTER_MSG;
	store16_le(msg->msg.len, IDENT_REGISTER_MSG_SIZE(username_len));
	msg->username_len = username_len;
	memcpy(msg->username, username, username_len);
	msg->username[username_len] = '\0';

	(void)state;

	return padme_enc(IDENT_REGISTER_MSG_SIZE(username_len));
}

size_t
ident_spksub_msg_init(struct ident_state *state, uint8_t *buf)
{
	struct ident_spksub_msg *msg = (struct ident_spksub_msg *)buf;
	struct keypair kp;

	generate_kex_keypair(kp.key.data, kp.prv);
	/* memcpy(kp.key.data, iks, 32); */
	/* memcpy(kp.prv, iks_prv, 32); */
	sign_key(kp.sig, state->isk_prv, state->isk, "AIBS", kp.key.data);

	stbds_hmputs(state->spks, kp);

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_SPKSUB_MSG;
	store16_le(msg->msg.len, IDENT_SPKSUB_MSG_SIZE);
	memcpy(msg->spk,     kp.key.data, 32);
	memcpy(msg->spk_sig, kp.sig,      64);

	return padme_enc(IDENT_SPKSUB_MSG_SIZE);
}

size_t
ident_lookup_msg_init(uint8_t *buf, const char *username)
{
	struct ident_lookup_msg *msg = (struct ident_lookup_msg *)buf;
	uint8_t len = strlen(username);

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_LOOKUP_MSG;
	store16_le(msg->msg.len, IDENT_LOOKUP_MSG_SIZE(len));
	msg->username_len = len;
	memcpy(msg->username, username, len);
	msg->username[len] = '\0';

	return padme_enc(IDENT_LOOKUP_MSG_SIZE(len));
}

size_t
ident_lookup_rep_init(uint8_t *buf, uint8_t isk[32])
{
	struct ident_lookup_reply_msg *msg = (struct ident_lookup_reply_msg *)buf;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_LOOKUP_REP;
	store16_le(msg->msg.len, sizeof *msg);
	memcpy(msg->isk, isk, 32);

	return padme_enc(sizeof *msg);
}

size_t
ident_reverse_lookup_msg_init(uint8_t *buf, uint8_t isk[32])
{
	struct ident_reverse_lookup_msg *msg = (struct ident_reverse_lookup_msg *)buf;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_REVERSE_LOOKUP_MSG;
	store16_le(msg->msg.len, IDENT_REVERSE_LOOKUP_MSG_SIZE);
	memcpy(msg->isk, isk, 32);

	return padme_enc(IDENT_REVERSE_LOOKUP_MSG_SIZE);
}

size_t
ident_reverse_lookup_rep_init(uint8_t *buf, const char *username)
{
	struct ident_reverse_lookup_reply_msg *msg = (struct ident_reverse_lookup_reply_msg *)buf;
	uint8_t len = strlen(username);

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_REVERSE_LOOKUP_REP;
	store16_le(msg->msg.len, IDENT_REVERSE_LOOKUP_REP_SIZE(len));
	msg->username_len = len;
	memcpy(msg->username, username, len);
	msg->username[len] = '\0';

	return padme_enc(IDENT_REVERSE_LOOKUP_REP_SIZE(len));
}

size_t
ident_keyreq_msg_init(struct ident_state *state, uint8_t *buf, const uint8_t isk[32])
{
	struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)buf;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_KEYREQ_MSG;
	store16_le(msg->msg.len, IDENT_KEYREQ_MSG_SIZE);
	memcpy(msg->isk, isk, 32);

	(void)state;

	return padme_enc(IDENT_KEYREQ_MSG_SIZE);
}

size_t
ident_keyreq_rep_init(uint8_t *buf, uint8_t spk[32], uint8_t spk_sig[64], uint8_t opk[32])
{
	struct ident_keyreq_reply_msg *msg = (struct ident_keyreq_reply_msg *)buf;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_KEYREQ_REP;
	store16_le(msg->msg.len, sizeof *msg);
	memcpy(msg->spk,     spk,     32);
	memcpy(msg->spk_sig, spk_sig, 64);
	memcpy(msg->opk,     opk,     32);

	return padme_enc(sizeof *msg);
}
