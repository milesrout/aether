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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msg.h"
#include "messaging.h"
#include "packet.h"
#include "util.h"

size_t
msg_fetch_init(uint8_t *buf)
{
	struct msg_fetch_msg *msg = (struct msg_fetch_msg *)PACKET_TEXT(buf);

	msg->msg.proto = PROTO_MSG;
	msg->msg.type = MSG_FETCH_MSG;
	store16_le(msg->msg.len, MSG_FETCH_MSG_SIZE);

	return padme_enc(MSG_FETCH_MSG_SIZE);
}

size_t
msg_forward_ack_init(uint8_t *buf, uint8_t result)
{
	struct msg_forward_ack_msg *msg = (struct msg_forward_ack_msg *)buf;

	msg->msg.proto = PROTO_MSG;
	msg->msg.type = MSG_FORWARD_ACK;
	store16_le(msg->msg.len, MSG_FORWARD_ACK_SIZE);
	msg->result = result;

	return padme_enc(MSG_FORWARD_ACK_SIZE);
}

size_t
msg_fetch_rep_init(uint8_t *buf, uint8_t msgcount, size_t totalmsglength)
{
	struct msg_fetch_reply_msg *msg = (struct msg_fetch_reply_msg *)buf;

	msg->msg.proto = PROTO_MSG;
	msg->msg.type = MSG_FETCH_REP;
	store16_le(msg->msg.len, MSG_FETCH_REP_SIZE(totalmsglength));
	msg->message_count = msgcount;

	return padme_enc(MSG_FETCH_REP_SIZE(totalmsglength));
}

size_t
msg_goodbye_init(uint8_t *buf, const uint8_t cv[32])
{
	struct msg_goodbye_msg *msg = (struct msg_goodbye_msg *)PACKET_TEXT(buf);

	msg->msg.proto = PROTO_MSG;
	msg->msg.type = MSG_GOODBYE_MSG;
	store16_le(msg->msg.len, MSG_GOODBYE_MSG_SIZE);
	if (cv == NULL)
		memset(msg->cv, 0, 32);
	else
		memcpy(msg->cv, cv, 32);

	return padme_enc(MSG_GOODBYE_MSG_SIZE);
}

size_t
msg_goodbye_ack_init(uint8_t *buf, const uint8_t cv[32])
{
	struct msg_goodbye_ack_msg *msg = (struct msg_goodbye_ack_msg *)buf;

	msg->msg.proto = PROTO_MSG;
	msg->msg.type = MSG_GOODBYE_ACK;
	store16_le(msg->msg.len, MSG_GOODBYE_ACK_SIZE);
	if (cv == NULL)
		memset(msg->cv, 0, 32);
	else
		memcpy(msg->cv, cv, 32);

	return padme_enc(MSG_GOODBYE_ACK_SIZE);
}
