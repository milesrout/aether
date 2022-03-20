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
#include <sys/types.h>

#include "queue.h"
#include "packet.h"
#include "msg.h"
#include "messaging.h"
#include "persist.h"
#include "util.h"

ssize_t
msg_nack_init(uint8_t *text, size_t size)
{
	size_t text_size = PACKET_TEXT_SIZE(size);
	size_t padded_size, padding;

	padded_size = padme_enc(MSG_NACK_SIZE);
	padding = padded_size - MSG_NACK_SIZE;

	if (persist_store8(PROTO_MSG,         &text, &text_size)) goto fail;
	if (persist_store8(MSG_NACK,          &text, &text_size)) goto fail;
	if (persist_store16_le(MSG_NACK_SIZE, &text, &text_size)) goto fail;
	if (persist_zeropad(padding,          &text, &text_size)) goto fail;

	return padded_size;
fail:
	return -1;
}

ssize_t
msg_fetch_init(uint8_t *text, size_t size)
{
	size_t text_size = PACKET_TEXT_SIZE(size);
	size_t padded_size, padding;

	padded_size = padme_enc(MSG_FETCH_MSG_SIZE);
	padding = padded_size - MSG_FETCH_MSG_SIZE;

	if (persist_store8(PROTO_MSG,              &text, &text_size)) goto fail;
	if (persist_store8(MSG_FETCH_MSG,          &text, &text_size)) goto fail;
	if (persist_store16_le(MSG_FETCH_MSG_SIZE, &text, &text_size)) goto fail;
	if (persist_zeropad(padding,               &text, &text_size)) goto fail;

	return padded_size;
fail:
	return -1;
}

ssize_t
msg_forward_ack_init(uint8_t *text, size_t size, uint8_t result)
{
	size_t text_size = PACKET_TEXT_SIZE(size);
	size_t padded_size, padding;

	padded_size = padme_enc(MSG_FORWARD_ACK_SIZE);
	padding = padded_size - MSG_FORWARD_ACK_SIZE;

	if (persist_store8(PROTO_MSG,       &text, &text_size)) goto fail;
	if (persist_store8(MSG_FORWARD_ACK, &text, &text_size)) goto fail;
	if (persist_store16_le(MSG_FORWARD_ACK_SIZE, &text, &text_size)) goto fail;
	if (persist_store8(result,          &text, &text_size)) goto fail;
	if (persist_zeropad(padding,        &text, &text_size)) goto fail;

	return padded_size;
fail:
	return -1;
}

ssize_t
msg_fetch_rep_init(uint8_t *text, size_t size, uint8_t msgcount, size_t totalmsglength)
{
	size_t msg_size = MSG_FETCH_REP_SIZE(totalmsglength);
	size_t text_size = PACKET_TEXT_SIZE(size);
	size_t padded_size, padding;

	padded_size = padme_enc(msg_size);
	padding = padded_size - msg_size;

	if (persist_store8(PROTO_MSG,     &text, &text_size)) goto fail;
	if (persist_store8(MSG_FETCH_REP, &text, &text_size)) goto fail;
	if (persist_store16_le(msg_size,  &text, &text_size)) goto fail;
	if (persist_store8(msgcount,      &text, &text_size)) goto fail;
	if (persist_zeropad(padding,      &text, &text_size)) goto fail;

	return padded_size;
fail:
	return -1;
}

ssize_t
msg_goodbye_init(uint8_t *text, size_t size, const uint8_t cv[32])
{
	size_t msg_size = MSG_GOODBYE_MSG_SIZE;
	size_t text_size = PACKET_TEXT_SIZE(size);
	size_t padded_size, padding;

	padded_size = padme_enc(msg_size);
	padding = padded_size - msg_size;

	if (persist_store8(PROTO_MSG,       &text, &text_size)) goto fail;
	if (persist_store8(MSG_GOODBYE_MSG, &text, &text_size)) goto fail;
	if (persist_store16_le(msg_size,    &text, &text_size)) goto fail;
	if (cv == NULL) {
		if (persist_zeropad(padding + 32, &text, &text_size)) goto fail;
	} else {
		if (persist_storebytes(cv, 32,    &text, &text_size)) goto fail;
		if (persist_zeropad(padding,      &text, &text_size)) goto fail;
	}

	return padded_size;
fail:
	return -1;
}

ssize_t
msg_goodbye_ack_init(uint8_t *text, size_t size, const uint8_t cv[32])
{
	size_t msg_size = MSG_GOODBYE_ACK_SIZE;
	size_t text_size = PACKET_TEXT_SIZE(size);
	size_t padded_size, padding;

	padded_size = padme_enc(msg_size);
	padding = padded_size - msg_size;

	if (persist_store8(PROTO_MSG,       &text, &text_size)) goto fail;
	if (persist_store8(MSG_GOODBYE_ACK, &text, &text_size)) goto fail;
	if (persist_store16_le(msg_size,    &text, &text_size)) goto fail;
	if (cv == NULL) {
		if (persist_zeropad(padding + 32, &text, &text_size)) goto fail;
	} else {
		if (persist_storebytes(cv, 32,    &text, &text_size)) goto fail;
		if (persist_zeropad(padding,      &text, &text_size)) goto fail;
	}

	return padded_size;
fail:
	return -1;
}
