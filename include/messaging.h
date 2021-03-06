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

#include "proto-messaging.h"

struct msg_nack_msg {
	struct msg msg;
};
#define MSG_NACK_SIZE (sizeof(struct msg_nack_msg))
struct msg_forward_msg {
	struct msg msg;
	uint8_t isk[32];
	uint8_t message_count;
	uint8_t messages[];
};
#define MSG_FORWARD_MSG_BASE_SIZE (sizeof(struct msg_forward_msg))
#define MSG_FORWARD_MSG_SIZE(n) (MSG_FORWARD_MSG_BASE_SIZE + (n))
struct msg_forward_ack_msg {
	struct msg msg;
	uint8_t result;
};
#define MSG_FORWARD_ACK_SIZE (sizeof(struct msg_forward_ack_msg))
struct msg_goodbye_msg {
	struct msg msg;
	uint8_t cv[32];
};
#define MSG_GOODBYE_MSG_SIZE (sizeof(struct msg_goodbye_msg))
struct msg_goodbye_ack_msg {
	struct msg msg;
	uint8_t cv[32];
};
#define MSG_GOODBYE_ACK_SIZE (sizeof(struct msg_goodbye_ack_msg))
struct msg_fetch_msg {
	struct msg msg;
};
#define MSG_FETCH_MSG_SIZE (sizeof(struct msg_fetch_msg))
struct msg_fetch_reply_msg {
	struct msg msg;
	uint8_t message_count;
	uint8_t messages[];
};
#define MSG_FETCH_REP_BASE_SIZE (sizeof(struct msg_fetch_reply_msg))
#define MSG_FETCH_REP_SIZE(n) (MSG_FETCH_REP_BASE_SIZE + (n))
struct msg_fetch_content_msg {
	uint8_t len[2];
	uint8_t isk[32];
	uint8_t text[];
};
#define MSG_FETCH_CONTENT_BASE_SIZE (sizeof(struct msg_fetch_content_msg))
#define MSG_FETCH_CONTENT_SIZE(n) (MSG_FETCH_CONTENT_BASE_SIZE + (n))
extern ssize_t msg_nack_init(uint8_t *text, size_t size);
extern ssize_t msg_forward_ack_init(uint8_t *text, size_t size, uint8_t result);
extern ssize_t msg_fetch_rep_init(uint8_t *text, size_t size, uint8_t message_count, size_t totalmsglength);
extern ssize_t msg_fetch_init(uint8_t *text, size_t size);
extern ssize_t msg_goodbye_ack_init(uint8_t *text, size_t size, const uint8_t cv[32]);
extern ssize_t msg_goodbye_init(uint8_t *text, size_t size, const uint8_t cv[32]);
