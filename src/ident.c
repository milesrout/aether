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
#include "queue.h"
#include "packet.h"
#include "msg.h"
#include "ident.h"
#include "persist.h"

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
ident_opkssub_msg_init(struct ident_state *state, uint8_t *text, size_t text_size)
{
	struct ident_opkssub_msg *msg = (struct ident_opkssub_msg *)text;
	uint8_t *next_key = text + sizeof *msg;
	int count = 0;
	int i;

	(void)text_size;

	count = fill_opks(state, MAX_OPKS);

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_OPKSSUB_MSG;
	store16_le(msg->msg.len, IDENT_OPKSSUB_MSG_SIZE(count));
	for (i = 0; i < count; i++) {
		memcpy(next_key, state->opks[MAX_OPKS - count + i].key.data, 32);
		next_key += 32;
	}
	store16_le(msg->opk_count, count);
	memset(text + IDENT_OPKSSUB_MSG_SIZE(count), 0, padme_enc(IDENT_OPKSSUB_MSG_SIZE(count)) - IDENT_OPKSSUB_MSG_SIZE(count));

	return padme_enc(IDENT_OPKSSUB_MSG_SIZE(count));
}

ssize_t
ident_opkssub_ack_init(uint8_t *text, size_t size, uint64_t id, uint64_t rid,
		uint8_t result)
{
	if (persist_store8(PROTO_IDENT,                &text, &size)) return -1;
	if (persist_store8(IDENT_OPKSSUB_ACK,          &text, &size)) return -1;
	if (persist_store16_le(IDENT_OPKSSUB_ACK_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,                     &text, &size)) return -1;
	if (persist_store64_le(rid,                    &text, &size)) return -1;
	if (persist_store8(result,                     &text, &size)) return -1;

	return IDENT_OPKSSUB_ACK_SIZE;
}

ssize_t
ident_spksub_ack_init(uint8_t *text, size_t size, uint64_t id, uint64_t rid,
		uint8_t result)
{
	if (persist_store8(PROTO_IDENT,               &text, &size)) return -1;
	if (persist_store8(IDENT_SPKSUB_ACK,          &text, &size)) return -1;
	if (persist_store16_le(IDENT_SPKSUB_ACK_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,                    &text, &size)) return -1;
	if (persist_store64_le(rid,                   &text, &size)) return -1;
	if (persist_store8(result,                    &text, &size)) return -1;

	return IDENT_SPKSUB_ACK_SIZE;
}

ssize_t
ident_register_ack_init(uint8_t *text, size_t size, uint64_t id, uint64_t rid,
		uint8_t result)
{
	if (persist_store8(PROTO_IDENT,                 &text, &size)) return -1;
	if (persist_store8(IDENT_REGISTER_ACK,          &text, &size)) return -1;
	if (persist_store16_le(IDENT_REGISTER_ACK_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,                      &text, &size)) return -1;
	if (persist_store64_le(rid,                     &text, &size)) return -1;
	if (persist_store8(result,                      &text, &size)) return -1;

	return IDENT_REGISTER_ACK_SIZE;
}

ssize_t
ident_lookup_rep_init(uint8_t *text, size_t size, uint64_t id, uint64_t rid,
		uint8_t isk[32])
{
	if (persist_store8(PROTO_IDENT,               &text, &size)) return -1;
	if (persist_store8(IDENT_LOOKUP_REP,          &text, &size)) return -1;
	if (persist_store16_le(IDENT_LOOKUP_REP_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,                    &text, &size)) return -1;
	if (persist_store64_le(rid,                   &text, &size)) return -1;
	if (persist_storebytes(isk, 32,               &text, &size)) return -1;

	return IDENT_LOOKUP_REP_SIZE;
}

ssize_t
ident_keyreq_rep_init(uint8_t *text, size_t size, uint64_t id, uint64_t rid,
		uint8_t spk[32], uint8_t spk_sig[64], uint8_t opk[32])
{
	if (persist_store8(PROTO_IDENT,               &text, &size)) return -1;
	if (persist_store8(IDENT_KEYREQ_REP,          &text, &size)) return -1;
	if (persist_store16_le(IDENT_KEYREQ_REP_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,                    &text, &size)) return -1;
	if (persist_store64_le(rid,                   &text, &size)) return -1;
	if (persist_storebytes(spk,     32,           &text, &size)) return -1;
	if (persist_storebytes(spk_sig, 64,           &text, &size)) return -1;
	if (persist_storebytes(opk,     32,           &text, &size)) return -1;

	return IDENT_KEYREQ_REP_SIZE;
}

size_t
ident_register_msg_init(struct ident_state *state, uint8_t *text, size_t text_size, char const *username)
{
	struct ident_register_msg *msg = (struct ident_register_msg *)text;
	uint8_t username_len = strlen(username);
	(void)text_size;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_REGISTER_MSG;
	store16_le(msg->msg.len, IDENT_REGISTER_MSG_SIZE(username_len));
	msg->username_len = username_len;
	memcpy(msg->username, username, username_len);
	msg->username[username_len] = '\0';
	memset(text + IDENT_REGISTER_MSG_SIZE(username_len), 0, padme_enc(IDENT_REGISTER_MSG_SIZE(username_len)) - IDENT_REGISTER_MSG_SIZE(username_len));

	(void)state;

	return padme_enc(IDENT_REGISTER_MSG_SIZE(username_len));
}

size_t
ident_spksub_msg_init(struct ident_state *state, uint8_t *text, size_t text_size)
{
	struct ident_spksub_msg *msg = (struct ident_spksub_msg *)text;
	struct keypair kp;
	(void)text_size;

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
	memset(text + IDENT_SPKSUB_MSG_SIZE, 0, padme_enc(IDENT_SPKSUB_MSG_SIZE) - IDENT_SPKSUB_MSG_SIZE);

	return padme_enc(IDENT_SPKSUB_MSG_SIZE);
}

size_t
ident_lookup_msg_init(uint8_t *text, size_t text_size, const char *username)
{
	struct ident_lookup_msg *msg = (struct ident_lookup_msg *)text;
	uint8_t len = strlen(username);
	(void)text_size;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_LOOKUP_MSG;
	store16_le(msg->msg.len, IDENT_LOOKUP_MSG_SIZE(len));
	msg->username_len = len;
	memcpy(msg->username, username, len);
	msg->username[len] = '\0';

	return padme_enc(IDENT_LOOKUP_MSG_SIZE(len));
}

size_t
ident_rlookup_msg_init(uint8_t *text, size_t text_size, uint8_t isk[32])
{
	struct ident_rlookup_msg *msg = (struct ident_rlookup_msg *)text;
	size_t msg_size = IDENT_RLOOKUP_MSG_SIZE;
	size_t padded_size = padme_enc(IDENT_RLOOKUP_MSG_SIZE);
	size_t padding = padded_size - msg_size;
	(void)text_size;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_RLOOKUP_MSG;
	store16_le(msg->msg.len, IDENT_RLOOKUP_MSG_SIZE);
	memcpy(msg->isk, isk, 32);
	memset(text + msg_size, 0, padding);

	return padme_enc(IDENT_RLOOKUP_MSG_SIZE);
}

size_t
ident_rlookup_rep_init(uint8_t *text, size_t text_size, const char *username)
{
	struct ident_rlookup_reply_msg *msg = (struct ident_rlookup_reply_msg *)text;
	uint8_t len = strlen(username);
	(void)text_size;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_RLOOKUP_REP;
	store16_le(msg->msg.len, IDENT_RLOOKUP_REP_SIZE(len));
	msg->username_len = len;
	memcpy(msg->username, username, len);
	msg->username[len] = '\0';

	return padme_enc(IDENT_RLOOKUP_REP_SIZE(len));
}

size_t
ident_keyreq_msg_init(struct ident_state *state, uint8_t *text, size_t text_size, const uint8_t isk[32])
{
	struct ident_keyreq_msg *msg = (struct ident_keyreq_msg *)text;
	(void)text_size;

	msg->msg.proto = PROTO_IDENT;
	msg->msg.type = IDENT_KEYREQ_MSG;
	store16_le(msg->msg.len, IDENT_KEYREQ_MSG_SIZE);
	memcpy(msg->isk, isk, 32);

	(void)state;

	return IDENT_KEYREQ_MSG_SIZE;
}
