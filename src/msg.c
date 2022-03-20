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
#include <sys/types.h>

#include "queue.h"
#include "packet.h"
#include "msg.h"
#include "proto-ident.h"
#include "proto-chat.h"
#include "proto-msg.h"
#include "persist.h"

const char *
msg_proto(uint8_t proto)
{
	switch (proto) {
		case PROTO_IDENT: return "IDENT";
		case PROTO_CHAT:  return "CHAT";
		case PROTO_MSG:   return "MSG";
		default: return "UNKNOWN";
	}
}

const char *
msg_type(uint8_t proto, uint8_t type)
{
	if (proto == PROTO_IDENT) {
		switch (type) {
			case IDENT_OPKSSUB_MSG:  return "OPKSSUB";
			case IDENT_OPKSSUB_ACK:  return "OPKSSUB_ACK";
			case IDENT_SPKSUB_MSG:   return "SPKSUB";
			case IDENT_SPKSUB_ACK:   return "SPKSUB_ACK";
			case IDENT_KEYREQ_MSG:   return "KEYREQ";
			case IDENT_KEYREQ_REP:   return "KEYREQ_REP";
			case IDENT_REGISTER_MSG: return "REGISTER";
			case IDENT_REGISTER_ACK: return "REGISTER_ACK";
			case IDENT_LOOKUP_MSG:   return "LOOKUP";
			case IDENT_LOOKUP_REP:   return "LOOKUP_REP";
			case IDENT_REVERSE_LOOKUP_MSG: return "REV_LOOKUP";
			case IDENT_REVERSE_LOOKUP_REP: return "REV_LOOKUP_REP";
			default: return "UNKNOWN";
		}
	} else if (proto == PROTO_CHAT) {
		switch (type) {
			case CHAT_NACK:        return "NACK";
			case CHAT_FORWARD_MSG: return "FORWARD";
			case CHAT_FORWARD_ACK: return "FORWARD_ACK";
			case CHAT_FETCH_MSG:   return "FETCH";
			case CHAT_FETCH_REP:   return "FETCH_REP";
			case CHAT_IMMEDIATE:   return "IMMEDIATE";
			case CHAT_GOODBYE_MSG: return "GOODBYE";
			case CHAT_GOODBYE_ACK: return "GOODBYE_ACK";
			default: return "UNKNOWN";
		}
	} else if (proto == PROTO_MSG) {
		switch (type) {
			case MSG_ACK:   return "ACK";
			case MSG_NACK:  return "NACK";
			case MSG_UNACK: return "UNACK";
			default: return "UNKNOWN";
		}
	} else return "UNKNOWN";
}

ssize_t
msg_ack_init(uint8_t *text, size_t size)
{
	size_t textsz = PACKET_TEXT_SIZE(size);
	size_t paddedsz, padding;

	paddedsz = padme_enc(MSG_ACK_SIZE);
	padding = paddedsz - MSG_ACK_SIZE;

	if (persist_store8(PROTO_MSG,        &text, &textsz)) goto fail;
	if (persist_store8(MSG_ACK,          &text, &textsz)) goto fail;
	if (persist_store16_le(MSG_ACK_SIZE, &text, &textsz)) goto fail;
	if (persist_zeropad(padding,         &text, &textsz)) goto fail;

	return paddedsz;
fail:
	return -1;
}

ssize_t
msg_nack_init(uint8_t *text, size_t size)
{
	size_t textsz = PACKET_TEXT_SIZE(size);
	size_t paddedsz, padding;

	paddedsz = padme_enc(MSG_NACK_SIZE);
	padding = paddedsz - MSG_NACK_SIZE;

	if (persist_store8(PROTO_MSG,         &text, &textsz)) goto fail;
	if (persist_store8(MSG_NACK,          &text, &textsz)) goto fail;
	if (persist_store16_le(MSG_NACK_SIZE, &text, &textsz)) goto fail;
	if (persist_zeropad(padding,          &text, &textsz)) goto fail;

	return paddedsz;
fail:
	return -1;
}

ssize_t
msg_unack_init(uint8_t *text, size_t size)
{
	size_t textsz = PACKET_TEXT_SIZE(size);
	size_t paddedsz, padding;

	paddedsz = padme_enc(MSG_UNACK_SIZE);
	padding = paddedsz - MSG_UNACK_SIZE;

	if (persist_store8(PROTO_MSG,          &text, &textsz)) goto fail;
	if (persist_store8(MSG_UNACK,          &text, &textsz)) goto fail;
	if (persist_store16_le(MSG_UNACK_SIZE, &text, &textsz)) goto fail;
	if (persist_zeropad(padding,           &text, &textsz)) goto fail;

	return paddedsz;
fail:
	return -1;
}
