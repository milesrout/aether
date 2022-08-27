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

#define MSG_BUFSZ 1500
struct msg {
	uint8_t proto;
	uint8_t type;
	uint8_t len[2];
	uint8_t id[8];
};
enum msg_event_type {
	MSGEV_UNKNOWN,
	MSGEV_IDENT_REGISTER,
	MSGEV_IDENT_SPKSUB,
	MSGEV_IDENT_OPKSSUB,
	MSGEV_IDENT_KEYREQ,
	MSGEV_IDENT_LOOKUP,
	MSGEV_IDENT_RLOOKUP,
	MSGEV_CHAT_FETCH,
	MSGEV_CHAT_FORWARD,
};
struct msg_event {
	uint8_t proto;
	uint8_t type;
	uint16_t len;
	uint64_t id;
	uint8_t *text;
	STAILQ_ENTRY(msg_event) eventq;
	/* union msg_event_args { */
	/* 	struct msg_event_unknown_args { */
	/* 		uint8_t *data; */
	/* 	} unknown; */
	/* 	struct msg_event_ident_register_args { */
	/* 		uint8_t *username; */
	/* 		uint8_t username_len; */
	/* 	} ident_register; */
	/* 	struct msg_event_ident_spksub_args { */
	/* 		uint8_t *spk; */
	/* 		uint8_t *spk_sig; */
	/* 	} ident_spksub; */
	/* 	struct msg_event_ident_opkssub_args { */
	/* 		uint8_t *opks; */
	/* 		uint8_t opk_count; */
	/* 	} ident_opkssub; */
	/* 	struct msg_event_ident_keyreq_args { */
	/* 		uint8_t *isk; */
	/* 	} ident_keyreq; */
	/* 	struct msg_event_ident_lookup_args { */
	/* 		uint8_t *username; */
	/* 		uint8_t username_len; */
	/* 	} ident_lookup; */
	/* 	struct msg_event_ident_rlookup_args { */
	/* 		uint8_t *isk; */
	/* 	} ident_rlookup; */
	/* 	struct msg_event_chat_forward_args { */
	/* 		uint8_t *isk; */
	/* 		uint8_t *message; */
	/* 		size_t message_len; */
	/* 	} chat_forward; */
	/* } args; */
};
STAILQ_HEAD(msgeventqhead, msg_event);
struct msg_buf {
	STAILQ_ENTRY(msg_buf) bufq;
	size_t  len;
	uint8_t buf[MSG_BUFSZ];
};
STAILQ_HEAD(msgsendqhead, msg_buf);
struct msg_state {
	union    packet_state ps;
	struct   msgeventqhead eventq;
	struct   msgsendqhead sendq;
	struct   msgsendqhead unackq;
	uint64_t unseen_start;  /* actual id assoc w/ acked[istart] */
	uint64_t unseen_ackd;   /* circular bitfield */
	int      unseen_istart; /* starting offset into bitfield */
	int      unseen_ilen;   /* length of current usage of bitfield */
};
extern int msg_next_event(struct msg_state *state, struct msg_event **ev);
extern int msg_set_success(struct msg_state *state, uint64_t id, int success);

extern const char *msg_proto(uint8_t);
extern const char *msg_type(uint8_t, uint8_t);

struct msg_ack_msg {
	struct msg msg;
};
#define MSG_ACK_SIZE (sizeof(struct msg_ack_msg))
struct msg_nack_msg {
	struct msg msg;
};
#define MSG_NACK_SIZE (sizeof(struct msg_nack_msg))
struct msg_unack_msg {
	struct msg msg;
};
#define MSG_UNACK_SIZE (sizeof(struct msg_unack_msg))
extern ssize_t msg_ack_init(uint8_t *text, size_t size, uint64_t id);
extern ssize_t msg_nack_init(uint8_t *text, size_t size, uint64_t id);
extern ssize_t msg_unack_init(uint8_t *text, size_t size, uint64_t id);
extern int msg_recv(struct msg_state *, uint8_t *, size_t);
extern int msg_send(struct msg_state *, uint8_t *, size_t, size_t *, char **, size_t *, size_t *);
