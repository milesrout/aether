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

#include "proto-ident.h"

struct ident_opkssub_msg {
	struct msg msg;
	uint8_t opk_count[2];	/* number of opks to submit (at most 2044?) */
	uint8_t opk[][32];
};
#define IDENT_OPKSSUB_MSG_BASE_SIZE (sizeof(struct ident_opkssub_msg))
#define IDENT_OPKSSUB_MSG_SIZE(n) (sizeof(struct ident_opkssub_msg) + 32 * (n))
struct ident_opkssub_ack_msg {
	struct msg msg;
	uint8_t result;
};
struct ident_spksub_msg {
	struct msg msg;
	uint8_t spk[32];
	uint8_t spk_sig[64];
};
#define IDENT_SPKSUB_MSG_SIZE (sizeof(struct ident_spksub_msg))
struct ident_spksub_ack_msg {
	struct msg msg;
	uint8_t result;
};
struct ident_keyreq_msg {
	struct msg msg;
	uint8_t isk[32];
};
#define IDENT_KEYREQ_MSG_SIZE (sizeof(struct ident_keyreq_msg))
struct ident_keyreq_reply_msg {
	struct msg msg;
	uint8_t spk[32];
	uint8_t spk_sig[64];
	uint8_t opk[32];
};
struct ident_register_msg {
	struct msg msg;
	uint8_t username_len;
	uint8_t username[];
};
#define IDENT_REGISTER_MSG_BASE_SIZE (sizeof(struct ident_register_msg))
#define IDENT_REGISTER_MSG_SIZE(n) (IDENT_REGISTER_MSG_BASE_SIZE + (n) + 1)
struct ident_register_ack_msg {
	struct msg msg;
	uint8_t result;
};
#define IDENT_REGISTER_ACK_SIZE (sizeof(struct ident_register_ack_msg))
struct ident_lookup_msg {
	struct msg msg;
	uint8_t username_len;
	uint8_t username[];
};
#define IDENT_LOOKUP_MSG_BASE_SIZE (sizeof(struct ident_lookup_msg))
#define IDENT_LOOKUP_MSG_SIZE(n) (IDENT_LOOKUP_MSG_BASE_SIZE + (n) + 1)
struct ident_lookup_reply_msg {
	struct msg msg;
	uint8_t isk[32];
};
#define IDENT_LOOKUP_REP_SIZE (sizeof(struct ident_lookup_reply_msg))
struct ident_reverse_lookup_msg {
	struct msg msg;
	uint8_t isk[32];
};
#define IDENT_REVERSE_LOOKUP_MSG_SIZE (sizeof(struct ident_reverse_lookup_msg))
struct ident_reverse_lookup_reply_msg {
	struct msg msg;
	uint8_t username_len;
	uint8_t username[];
};
#define IDENT_REVERSE_LOOKUP_REP_BASE_SIZE (sizeof(struct ident_reverse_lookup_reply_msg))
#define IDENT_REVERSE_LOOKUP_REP_SIZE(n) (IDENT_REVERSE_LOOKUP_REP_BASE_SIZE + (n) + 1)
struct key {
	uint8_t data[32];
};
struct keypair {
	struct key key;
	uint8_t prv[32];
	uint8_t sig[64];
};
struct ident_state {
	uint8_t isk[32];
	uint8_t isk_prv[32];
	uint8_t ik[32];
	uint8_t ik_prv[32];
	struct keypair *opks;
	struct keypair *spks;
	const char *username;
};
extern size_t ident_opkssub_msg_init(struct ident_state *, uint8_t *text, size_t text_size);
extern size_t ident_opkssub_ack_init(uint8_t *text, size_t text_size, uint8_t result);
extern size_t ident_spksub_msg_init(struct ident_state *, uint8_t *text, size_t text_size);
extern size_t ident_spksub_ack_init(uint8_t *text, size_t text_size, uint8_t result);
extern size_t ident_keyreq_msg_init(struct ident_state *, uint8_t *text, size_t text_size, const uint8_t isk[32]);
extern size_t ident_keyreq_rep_init(uint8_t *text, size_t text_size, uint8_t spk[32], uint8_t spk_sig[64], uint8_t opk[32]);
extern size_t ident_register_msg_init(struct ident_state *, uint8_t *text, size_t text_size, char const *username);
extern size_t ident_register_ack_init(uint8_t *text, size_t text_size, uint8_t result);
extern size_t ident_lookup_msg_init(uint8_t *text, size_t text_size, char const *username);
extern size_t ident_lookup_rep_init(uint8_t *text, size_t text_size, uint8_t isk[32]);
extern size_t ident_reverse_lookup_msg_init(uint8_t *text, size_t text_size, uint8_t isk[32]);
extern size_t ident_reverse_lookup_rep_init(uint8_t *text, size_t text_size, const char *username);
