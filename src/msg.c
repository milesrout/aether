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

#include "msg.h"
#include "ident.h"
#include "messaging.h"

const char *
msg_proto(uint8_t proto)
{
	switch (proto) {
		case PROTO_IDENT: return "IDENT";
		case PROTO_MSG: return "MSG";
		default: return "UNKNOWN";
	}
}

const char *
msg_type(uint8_t proto, uint8_t type)
{
	if (proto == PROTO_IDENT) {
		switch (type) {
			case IDENT_OPKSSUB_MSG: return "OPKSSUB";
			case IDENT_OPKSSUB_ACK: return "OPKSSUB_ACK";
			case IDENT_SPKSUB_MSG: return "SPKSUB";
			case IDENT_SPKSUB_ACK: return "SPKSUB_ACK";
			case IDENT_KEYREQ_MSG: return "KEYREQ";
			case IDENT_KEYREQ_REP: return "KEYREQ_REP";
			case IDENT_REGISTER_MSG: return "REGISTER";
			case IDENT_REGISTER_ACK: return "REGISTER_ACK";
			case IDENT_LOOKUP_MSG: return "LOOKUP";
			case IDENT_LOOKUP_REP: return "LOOKUP_REP";
			case IDENT_REVERSE_LOOKUP_MSG: return "REV_LOOKUP";
			case IDENT_REVERSE_LOOKUP_REP: return "REV_LOOKUP_REP";
			default: return "UKNOWNN";
		}
	} else if (proto == PROTO_MSG) {
		switch (type) {
			case MSG_NACK: return "NACK";
			case MSG_FORWARD_MSG: return "FORWARD";
			case MSG_FORWARD_ACK: return "FORWARD_ACK";
			case MSG_FETCH_MSG: return "FETCH";
			case MSG_FETCH_REP: return "FETCH_REP";
			case MSG_IMMEDIATE: return "IMMEDIATE";
			case MSG_GOODBYE_MSG: return "GOODBYE";
			case MSG_GOODBYE_ACK: return "GOODBYE_ACK";
			default: return "UKNOWNN";
		}
	} else {
		return "UNKNOWN";
	}
}

