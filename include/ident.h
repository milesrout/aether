#define IDENT_OPKSSUB_MSG ((uint8_t)1)
#define IDENT_SPKSUB_MSG ((uint8_t)2)
#define IDENT_KEYREQ_MSG ((uint8_t)3)
#define IDENT_OPKSSUB_ACK ((uint8_t)-1)
#define IDENT_SPKSUB_ACK ((uint8_t)-2)
#define IDENT_KEYREQ_REP ((uint8_t)-3)
struct ident_opkssub_msg {
	uint8_t msgtype;
	uint8_t opk_count[2];	/* number of opks to submit (at most 2044?) */
	uint8_t opk[][32];
};
#define OPK_SUBMISSION_SIZE(n) (sizeof(struct ident_opkssub_msg) + 32 * (n))
struct ident_opkssub_ack_msg {
	uint8_t msgtype;
	uint8_t msn[4];
};
struct ident_spksub_msg {
	uint8_t msgtype;
	uint8_t spk[32];
	uint8_t spk_sig[64];
};
struct ident_spksub_ack_msg {
	uint8_t msgtype;
	uint8_t msn[4];
};
struct ident_keyreq_msg {
	uint8_t msgtype;
	uint8_t ik[32];
};
struct ident_keyreq_reply_msg {
	uint8_t msgtype;
	uint8_t msn[4];
	uint8_t spk[32];
	uint8_t spk_sig[64];
	uint8_t opk[32];
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
extern void ident_opkssub_msg_init(struct ident_state *, uint8_t *buf);
extern void ident_spksub_msg_init(struct ident_state *, uint8_t *buf);
extern void ident_keyreq_msg_init(struct ident_state *, uint8_t *buf, const uint8_t ik[32]);
extern void ident_opkssub_ack_init(struct ident_state *, uint8_t *buf, uint8_t ik[32]);
extern void ident_spksub_ack_init(struct ident_state *, uint8_t *buf, uint8_t ik[32]);
extern void ident_keyreq_rep_init(struct ident_state *, uint8_t *buf, uint8_t ik[32]);

extern void ident_opkssub_msg_reply(struct client_ident_state *state, struct ident_opkssub_msg *msg);
