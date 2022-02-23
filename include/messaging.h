#define PROTO_MSG ((uint8_t)2)
#define MSG_FORWARD_MSG ((uint8_t)2)
#define MSG_FORWARD_ACK ((uint8_t)3)
#define MSG_FETCH_MSG ((uint8_t)4)
#define MSG_FETCH_REP ((uint8_t)5)
#define MSG_IMMEDIATE ((uint8_t)6)
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
	uint8_t msn[4];
	uint8_t result;
};
#define MSG_FORWARD_ACK_SIZE (sizeof(struct msg_forward_ack_msg))
struct msg_fetch_msg {
	struct msg msg;
};
#define MSG_FETCH_MSG_SIZE (sizeof(struct msg_fetch_msg))
struct msg_fetch_reply_msg {
	struct msg msg;
	uint8_t msn[4];
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
extern size_t msg_forward_ack_init(uint8_t *buf, uint8_t msn[4], uint8_t result);
extern size_t msg_fetch_rep_init(uint8_t *buf, uint8_t msn[4], uint8_t message_count, size_t totalmsglength);
extern size_t msg_fetch_init(uint8_t *buf);
