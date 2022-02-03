#define IDENT_OPKSSUB_MSG ((uint8_t)2)
#define IDENT_OPKSSUB_ACK ((uint8_t)3)
#define IDENT_SPKSUB_MSG ((uint8_t)4)
#define IDENT_SPKSUB_ACK ((uint8_t)5)
#define IDENT_KEYREQ_MSG ((uint8_t)6)
#define IDENT_KEYREQ_REP ((uint8_t)7)
#define IDENT_REGISTER_MSG ((uint8_t)8)
#define IDENT_REGISTER_ACK ((uint8_t)9)
#define IDENT_LOOKUP_MSG ((uint8_t)10)
#define IDENT_LOOKUP_REP ((uint8_t)11)
#define IDENT_FORWARD_MSG ((uint8_t)12)
#define IDENT_FORWARD_ACK ((uint8_t)13)
#define IDENT_FETCH_MSG ((uint8_t)14)
#define IDENT_FETCH_REP ((uint8_t)15)
struct ident_opkssub_msg {
	uint8_t msgtype;
	uint8_t opk_count[2];	/* number of opks to submit (at most 2044?) */
	uint8_t opk[][32];
};
#define IDENT_OPKSSUB_MSG_BASE_SIZE (sizeof(struct ident_opkssub_msg))
#define IDENT_OPKSSUB_MSG_SIZE(n) (sizeof(struct ident_opkssub_msg) + 32 * (n))
struct ident_opkssub_ack_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	uint8_t result;
};
struct ident_spksub_msg {
	uint8_t msgtype;
	uint8_t spk[32];
	uint8_t spk_sig[64];
};
#define IDENT_SPKSUB_MSG_SIZE (sizeof(struct ident_spksub_msg))
struct ident_spksub_ack_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	uint8_t result;
};
struct ident_keyreq_msg {
	uint8_t msgtype;
	uint8_t isk[32];
};
#define IDENT_KEYREQ_MSG_SIZE (sizeof(struct ident_keyreq_msg))
struct ident_keyreq_reply_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	/* uint8_t ik[32]; */
	/* uint8_t ik_sig[64]; */
	uint8_t spk[32];
	uint8_t spk_sig[64];
	uint8_t opk[32];
};
#define IDENT_REGISTER_MSG_BASE_SIZE (sizeof(struct ident_register_msg))
#define IDENT_REGISTER_MSG_SIZE(n) (IDENT_REGISTER_MSG_BASE_SIZE + (n) + 1)
struct ident_register_msg {
	uint8_t msgtype;
	uint8_t username_len;
	uint8_t username[];
};
#define IDENT_REGISTER_ACK_SIZE (sizeof(struct ident_register_ack_msg))
struct ident_register_ack_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	uint8_t result;
};
#define IDENT_LOOKUP_MSG_BASE_SIZE (sizeof(struct ident_lookup_msg))
#define IDENT_LOOKUP_MSG_SIZE(n) (IDENT_LOOKUP_MSG_BASE_SIZE + (n) + 1)
struct ident_lookup_msg {
	uint8_t msgtype;
	uint8_t username_len;
	uint8_t username[];
};
struct ident_lookup_reply_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	uint8_t isk[32];
};
#define IDENT_FORWARD_MSG_BASE_SIZE (sizeof(struct ident_forward_msg))
#define IDENT_FORWARD_MSG_SIZE(n) (IDENT_FORWARD_MSG_BASE_SIZE + (n))
struct ident_forward_msg {
	uint8_t msgtype;
	uint8_t isk[32];
	uint8_t message_count;
	uint8_t messages[];
};
#define IDENT_FORWARD_ACK_SIZE (sizeof(struct ident_forward_ack_msg))
struct ident_forward_ack_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	uint8_t result;
};
#define IDENT_FETCH_MSG_BASE_SIZE (sizeof(struct ident_fetch_msg))
#define IDENT_FETCH_MSG_SIZE(n) (IDENT_FETCH_MSG_BASE_SIZE + (n) + 1)
struct ident_fetch_msg {
	uint8_t msgtype;
};
struct ident_fetch_reply_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	uint8_t message_count;
	uint8_t messages[];
};
struct ident_state {
	uint8_t isk[32];
	uint8_t isk_prv[32];
	uint8_t ik[32];
	uint8_t ik_prv[32];
	uint8_t opk_prvs[32][32];
	uint8_t spk_prv[32];
	uint8_t oldspk_prv[32];
};
struct client_ident_state {
	uint8_t isk[32];
	uint8_t ik[32];
	uint8_t opks[8][32];
	uint8_t opks_valid;
	uint8_t spk[32];
};
extern size_t ident_opkssub_msg_init(struct ident_state *, uint8_t *buf);
extern size_t ident_opkssub_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result);
extern size_t ident_spksub_msg_init(struct ident_state *, uint8_t *buf);
extern size_t ident_spksub_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result);
extern size_t ident_keyreq_msg_init(struct ident_state *, uint8_t *buf, const uint8_t isk[32]);
extern size_t ident_keyreq_rep_init(uint8_t *buf, uint8_t msn[4],
	/* uint8_t ik[32], uint8_t ik_sig[64], */
	uint8_t spk[32], uint8_t spk_sig[64], uint8_t opk[32]);
extern size_t ident_register_msg_init(struct ident_state *, uint8_t *buf, char const *username);
extern size_t ident_register_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result);
extern size_t ident_lookup_msg_init(struct ident_state *, uint8_t *buf, char const *username);
extern size_t ident_lookup_rep_init(uint8_t *buf, uint8_t msn[4], uint8_t isk[32]);
extern size_t ident_forward_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result);
extern size_t ident_fetch_rep_init(uint8_t *buf, uint8_t msn[4], uint8_t message_count);

extern void ident_opkssub_msg_reply(struct client_ident_state *state, struct ident_opkssub_msg *msg);
