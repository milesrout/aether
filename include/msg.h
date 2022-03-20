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

#include "proto-msg.h"

struct msg {
	uint8_t proto;
	uint8_t type;
	uint8_t len[2];
};
struct msg_state {
	union packet_state ps;
};
extern const char *msg_proto(uint8_t);
extern const char *msg_type(uint8_t, uint8_t);

struct msg_ack_msg {
	struct msg msg;
	uint64_t msgid;
};
#define MSG_ACK_SIZE (sizeof(struct msg_ack_msg))
struct msg_nack_msg {
	struct msg msg;
	uint64_t msgid;
};
#define MSG_NACK_SIZE (sizeof(struct msg_nack_msg))
struct msg_unack_msg {
	struct msg msg;
	uint64_t msgid;
};
#define MSG_UNACK_SIZE (sizeof(struct msg_unack_msg))
extern ssize_t msg_ack_init(uint8_t *text, size_t size);
extern ssize_t msg_nack_init(uint8_t *text, size_t size);
extern ssize_t msg_unack_init(uint8_t *text, size_t size);
