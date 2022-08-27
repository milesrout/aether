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

#include <err.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "queue.h"
#include "packet.h"
#include "msg.h"
#include "ident.h"
#include "chat.h"
#include "persist.h"
#include "util.h"

const char *
msg_proto(uint8_t proto)
{
	switch (proto) {
		case PROTO_IDENT: return "IDENT";
		case PROTO_CHAT:  return "CHAT";
		case PROTO_MSG:   return "MSG";
		default:          return "UNKNOWN";
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
			case IDENT_RLOOKUP_MSG:  return "RLOOKUP";
			case IDENT_RLOOKUP_REP:  return "RLOOKUP_REP";
			default:                 return "UNKNOWN";
		}
	} else if (proto == PROTO_CHAT) {
		switch (type) {
			case CHAT_FORWARD_MSG: return "FORWARD";
			case CHAT_FORWARD_ACK: return "FORWARD_ACK";
			case CHAT_FETCH_MSG:   return "FETCH";
			case CHAT_FETCH_REP:   return "FETCH_REP";
			case CHAT_IMMEDIATE:   return "IMMEDIATE";
			case CHAT_GOODBYE_MSG: return "GOODBYE";
			case CHAT_GOODBYE_ACK: return "GOODBYE_ACK";
			default:               return "UNKNOWN";
		}
	} else if (proto == PROTO_MSG) {
		switch (type) {
			case MSG_ACK:   return "ACK";
			case MSG_NACK:  return "NACK";
			case MSG_UNACK: return "UNACK";
			default:        return "UNKNOWN";
		}
	} else return "UNKNOWN";
}

ssize_t
msg_ack_init(uint8_t *text, size_t size, uint64_t id)
{
	if (persist_store8(PROTO_MSG,        &text, &size)) return -1;
	if (persist_store8(MSG_ACK,          &text, &size)) return -1;
	if (persist_store16_le(MSG_ACK_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,           &text, &size)) return -1;

	return MSG_ACK_SIZE;
}

ssize_t
msg_nack_init(uint8_t *text, size_t size, uint64_t id)
{
	if (persist_store8(PROTO_MSG,         &text, &size)) return -1;
	if (persist_store8(MSG_NACK,          &text, &size)) return -1;
	if (persist_store16_le(MSG_NACK_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,            &text, &size)) return -1;

	return MSG_NACK_SIZE;
}

ssize_t
msg_unack_init(uint8_t *text, size_t size, uint64_t id)
{
	if (persist_store8(PROTO_MSG,          &text, &size)) return -1;
	if (persist_store8(MSG_UNACK,          &text, &size)) return -1;
	if (persist_store16_le(MSG_UNACK_SIZE, &text, &size)) return -1;
	if (persist_store64_le(id,             &text, &size)) return -1;

	return MSG_UNACK_SIZE;
}

enum {
	AW_SUCCESS = 0,
	AW_FAILURE = 1,
};

/* static */
/* struct msg_event * */
/* ev_create(int type, uint64_t id) */
/* { */
/* 	struct msg_event *ev; */

/* 	/1* TODO: use a spares list *1/ */
/* 	ev = malloc(sizeof *ev); */
/* 	if (!ev) err(1, "out of memory"); */

/* 	ev->type = type; */
/* 	ev->id = id; */

/* 	return ev; */
/* } */

int
msg_next_event(struct msg_state *state, struct msg_event **ev)
{
	if (*ev = STAILQ_FIRST(&state->eventq)) {
		STAILQ_REMOVE_HEAD(&state->eventq, eventq);
		return 1;
	}
	return 0;
}

static void
appendfmt(char **pstr, size_t *psize, size_t *plen, const char *fmt, ...)
{
	va_list args;
	int size;
	char *tmp;

	if (*pstr == NULL) {
		va_start(args, fmt);
		size = vasprintf(pstr, fmt, args);
		va_end(args);

		if (size == -1)
			err(1, "out of memory");

		*psize = size + 1;
		*plen = size;

		return;
	}

	va_start(args, fmt);
	size = vsnprintf(*pstr + *plen, *psize - *plen, fmt, args);
	va_end(args);

	if ((size_t)size < *psize - *plen) {
		*plen += size;
		return;
	}

	tmp = realloc(*pstr, *plen + size + 1);
	if (!tmp) err(1, "out of memory");
	*pstr = tmp;
	*psize = *plen + size + 1;

	va_start(args, fmt);
	size = vsnprintf(*pstr + *plen, *psize - *plen, fmt, args);
	va_end(args);
	*plen += size;
}

/* int ident_register_ack(struct msg_state *state, uint64_t id, int result); */
/* int ident_spksub_ack(struct msg_state *state, uint64_t id, int result); */

/* int */
/* ident_register_ack(struct msg_state *state, uint64_t id, int result) */
/* { */
/* 	struct msg_buf *msgbuf; */
/* 	ssize_t slen; */

/* 	msgbuf = malloc(sizeof(struct msg_buf)); */
/* 	if (!msgbuf) return -1; */

/* 	slen = ident_register_ack_init(msgbuf->buf, MSG_BUFSZ, 0, id, result); */
/* 	if (slen == -1) { */
/* 		free(msgbuf); */
/* 		return -1; */
/* 	} */

/* 	msgbuf->len = (size_t)slen; */
/* 	STAILQ_INSERT_TAIL(&state->sendq, msgbuf, bufq); */
/* 	return 0; */
/* } */

/* int */
/* ident_spksub_ack(struct msg_state *state, uint64_t id, int result) */
/* { */
/* 	struct msg_buf *msgbuf; */
/* 	ssize_t slen; */

/* 	msgbuf = malloc(sizeof(struct msg_buf)); */
/* 	if (!msgbuf) return -1; */

/* 	slen = ident_spksub_ack_init(msgbuf->buf, MSG_BUFSZ, 0, id, result); */
/* 	if (slen == -1) { */
/* 		free(msgbuf); */
/* 		return -1; */
/* 	} */

/* 	msgbuf->len = (size_t)slen; */
/* 	STAILQ_INSERT_TAIL(&state->sendq, msgbuf, bufq); */
/* 	return 0; */
/* } */

int
msg_send(struct msg_state *state, uint8_t *buf, size_t bufsz, size_t *plen,
		char **pdesc, size_t *pdescsize, size_t *pdesclen)
{
	struct msg_buf *msgbuf;
	size_t textsz, len;
	uint8_t *text;
	int ret = 0;
	uint8_t proto, type;
	const char *proto_str;
	const char *type_str;

	text = PACKET_TEXT(buf);
	textsz = PACKET_TEXT_SIZE(bufsz);
	len = 0;

	/* fprintf(stderr, "msg_send: bufsz=%lu\n", bufsz); */

	while (msgbuf = STAILQ_FIRST(&state->sendq)) {
		/* fprintf(stderr, "msg_send: msgbuf=%p\n", (void *)msgbuf); */

		/* if there are no messages to send, we're done */
		if (!msgbuf)
			goto end;

		/* if the next message wouldn't fit in this packet, we are done */
		/*
		 * NOTE that it is possible that the optimal thing to do here
		 * would be to search the rest of the send queue to see whether
		 * there are any more messages that would fit in the rest of
		 * this packet, but that currently we use a singly-linked tail
		 * queue which seems to make that kind of search and extraction
		 * from the middle of the list a little tricky or inefficient.
		 * for now, we will just send messages in the order they appear
		 * in the queue, but note that this may change in the future.
		 */
		if (textsz <= msgbuf->len)
			goto end;

		/* we can definitely send the next message, so can safely
		 * remove it from the queue */
		STAILQ_REMOVE_HEAD(&state->sendq, bufq);

		/* logging */
		proto = msgbuf->buf[0];
		type = msgbuf->buf[1];
		proto_str = msg_proto(proto);
		type_str = msg_type(proto, type);
		appendfmt(pdesc, pdescsize, pdesclen,
			/* ret ? ",%d/%d=%s/%s" : "%d/%d=%s/%s", */
			/* proto, type, proto_str, type_str); */
			ret ? ",%s/%s" : "%s/%s",
			proto_str, type_str);

		memcpy(text, msgbuf->buf, msgbuf->len);
		text += msgbuf->len;
		textsz -= msgbuf->len;
		len += msgbuf->len;
		ret = 1;

		/* msgbuf should be stored where it can be resent in the event
		 * of a resubmission (NACK) */
		free(msgbuf);
		/* displaykey("msg_send/msgbuf", msgbuf->buf, msgbuf->len); */
	}

end:
	if (ret) {
		size_t paddedsz = padme_enc(len);
		size_t padding = paddedsz - len;

		/* displaykey("msg_send/packet", PACKET_TEXT(buf), len); */
		if (persist_zeropad(padding, &text, &textsz))
			errx(1, "not enough room for padding");
		packet_lock(&state->ps, buf, paddedsz);
		*plen = PACKET_BUF_SIZE(paddedsz);
	}

	return ret;
}

int
msg_recv(struct msg_state *state, uint8_t *buf, size_t nread)
{
	uint8_t  *text, *content;
	struct    msg_event *ev;
	struct    msg *hdr;
	ptrdiff_t size;
	uint16_t  len;
	uint64_t  id;

	text = PACKET_TEXT(buf);
	size = PACKET_TEXT_SIZE(nread);

	if (packet_unlock(&state->ps, buf, nread)) {
		printf("INVALID\n");
		return -1;
	}

	if ((size_t)size < sizeof(struct msg)) {
		printf("UNKNOWN\n");
		return -1;
	}

	while (size > 0) {
		/* fprintf(stderr, "%ld of %lu\n", size, PACKET_TEXT_SIZE(nread)); */
		hdr = (struct msg *)text;

		if (hdr->proto == 0 || hdr->type == 0)
			break;

		content = text + sizeof(struct msg);
		id = load64_le(hdr->id);

		printf("%d/%d\t%s/%s\n", hdr->proto, hdr->type,
			msg_proto(hdr->proto),
			msg_type(hdr->proto, hdr->type));

		/* check that the len field in the message
		 * doesn't overrun the buffer */
		len = load16_le(hdr->len);
		if (len > size)
			break;

		if (len == 0)
			break;

		text += len;
		size -= len;

		/* if (id < state->unseen_start) { */
		{
			struct msg_buf *msgbuf;
			ssize_t slen;

			msgbuf = malloc(sizeof(struct msg_buf));
			if (!msgbuf) return -1;

			slen = msg_ack_init(msgbuf->buf, MSG_BUFSZ, id);
			if (slen == -1) {
				free(msgbuf);
				return -1;
			}
			/* fprintf(stderr, "ack len=%ld\n", slen); */
			msgbuf->len = (size_t)slen;
			STAILQ_INSERT_TAIL(&state->sendq, msgbuf, bufq);
		}

		if (hdr->proto == PROTO_MSG) {
			switch (hdr->type) {
				case MSG_ACK:
					/* record_as_acked(); */
					return 0;
				case MSG_NACK:
					/* if (we_still_have_it) */
					/* 	send_it(); */
					/* else */
					/* 	dunno(); */
					return 0;
				case MSG_UNACK:
					/* if (we_have_received_it) */
					/* 	send_ack(); */
					/* else */
					/* 	send_nack(); */
					return 0;
				default:
					return -1;
			}
		} else {
			ev = malloc(sizeof *ev);
			if (!ev) err(1, "out of memory");
			ev->proto = hdr->proto;
			ev->type = hdr->type;
			ev->len = len;
			ev->id = id;
			ev->text = content;
			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq);
		}
	}
	/* } else if (hdr->proto == PROTO_IDENT) { */
	/* 	switch (hdr->type) { */
	/* 		case IDENT_REGISTER_MSG: { */
	/* 			struct ident_register_msg *identmsg = (void *)text; */
	/* 			ev = ev_create(MSGEV_IDENT_REGISTER, id); */
	/* 			ev->args.ident_register.username_len = identmsg->username_len; */
	/* 			ev->args.ident_register.username = identmsg->username; */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 		case IDENT_SPKSUB_MSG: { */
	/* 			struct ident_spksub_msg *identmsg = (void *)text; */
	/* 			ev = ev_create(MSGEV_IDENT_SPKSUB, id); */
	/* 			ev->args.ident_spksub.spk = identmsg->spk; */
	/* 			ev->args.ident_spksub.spk_sig = identmsg->spk_sig; */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 		case IDENT_OPKSSUB_MSG: { */
	/* 			struct ident_opkssub_msg *identmsg = (void *)text; */
	/* 			ev = ev_create(MSGEV_IDENT_OPKSSUB, id); */
	/* 			ev->args.ident_opkssub.opk_count = load16_le(identmsg->opk_count); */
	/* 			ev->args.ident_opkssub.opks = identmsg->opk[0]; */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 		case IDENT_LOOKUP_MSG: { */
	/* 			struct ident_lookup_msg *identmsg = (void *)text; */
	/* 			ev = ev_create(MSGEV_IDENT_LOOKUP, id); */
	/* 			ev->args.ident_lookup.username_len = identmsg->username_len; */
	/* 			ev->args.ident_lookup.username = identmsg->username; */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 		case IDENT_RLOOKUP_MSG: { */
	/* 			struct ident_rlookup_msg *identmsg = (void *)text; */
	/* 			ev = ev_create(MSGEV_IDENT_RLOOKUP, id); */
	/* 			ev->args.ident_rlookup.isk = identmsg->isk; */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 		case IDENT_KEYREQ_MSG: { */
	/* 			struct ident_keyreq_msg *identmsg = (void *)text; */
	/* 			ev = ev_create(MSGEV_IDENT_KEYREQ, id); */
	/* 			ev->args.ident_keyreq.isk = identmsg->isk; */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 	} */
	/* } else if (hdr->proto == PROTO_CHAT) { */
	/* 	switch (hdr->type) { */
	/* 		case CHAT_FETCH_MSG: { */
	/* 			ev = ev_create(MSGEV_CHAT_FETCH, id); */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 		case CHAT_FORWARD_MSG: { */
	/* 			struct chat_forward_msg *chatmsg = (void *)text; */
	/* 			ev = ev_create(MSGEV_CHAT_FORWARD, id); */
	/* 			ev->args.chat_forward.isk = chatmsg->isk; */
	/* 			ev->args.chat_forward.isk = chatmsg->isk; */
	/* 			STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* 			return 0; */
	/* 		} */
	/* 	} */
	/* } */

	/* ev = ev_create(MSGEV_UNKNOWN, id); */
	/* ev->args.unknown.data = content; */
	/* STAILQ_INSERT_TAIL(&state->eventq, ev, eventq); */
	/* return 0; */
	return 0;
}

