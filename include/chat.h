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

#include "proto-chat.h"

struct chat_nack_msg {
	struct msg msg;
};
#define CHAT_NACK_SIZE (sizeof(struct chat_nack_msg))
struct chat_forward_msg {
	struct msg msg;
	uint8_t isk[32];
	uint8_t message_count;
	uint8_t messages[];
};
#define CHAT_FORWARD_MSG_BASE_SIZE (sizeof(struct chat_forward_msg))
#define CHAT_FORWARD_MSG_SIZE(n) (CHAT_FORWARD_MSG_BASE_SIZE + (n))
struct chat_forward_ack_msg {
	struct msg msg;
	uint8_t result;
};
#define CHAT_FORWARD_ACK_SIZE (sizeof(struct chat_forward_ack_msg))
struct chat_goodbye_msg {
	struct msg msg;
	uint8_t cv[32];
};
#define CHAT_GOODBYE_MSG_SIZE (sizeof(struct chat_goodbye_msg))
struct chat_goodbye_ack_msg {
	struct msg msg;
	uint8_t cv[32];
};
#define CHAT_GOODBYE_ACK_SIZE (sizeof(struct chat_goodbye_ack_msg))
struct chat_fetch_msg {
	struct msg msg;
};
#define CHAT_FETCH_MSG_SIZE (sizeof(struct chat_fetch_msg))
struct chat_fetch_reply_msg {
	struct msg msg;
	uint8_t message_count;
	uint8_t messages[];
};
#define CHAT_FETCH_REP_BASE_SIZE (sizeof(struct chat_fetch_reply_msg))
#define CHAT_FETCH_REP_SIZE(n) (CHAT_FETCH_REP_BASE_SIZE + (n))
struct chat_fetch_content_msg {
	uint8_t len[2];
	uint8_t isk[32];
	uint8_t text[];
};
#define CHAT_FETCH_CONTENT_BASE_SIZE (sizeof(struct chat_fetch_content_msg))
#define CHAT_FETCH_CONTENT_SIZE(n) (CHAT_FETCH_CONTENT_BASE_SIZE + (n))
extern ssize_t chat_nack_init(uint8_t *text, size_t size);
extern ssize_t chat_forward_ack_init(uint8_t *text, size_t size, uint8_t result);
extern ssize_t chat_fetch_rep_init(uint8_t *text, size_t size, uint8_t message_count, size_t totalchatlength);
extern ssize_t chat_fetch_init(uint8_t *text, size_t size);
extern ssize_t chat_goodbye_ack_init(uint8_t *text, size_t size, const uint8_t cv[32]);
extern ssize_t chat_goodbye_init(uint8_t *text, size_t size, const uint8_t cv[32]);
