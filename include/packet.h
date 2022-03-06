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

struct packethdr {
	uint8_t hdrmac[16];
	uint8_t nonce[24];
	uint8_t mac[16];
	uint8_t msn[4];
	uint8_t pn[4];
	uint8_t pk[32];
};
struct packet {
	struct packethdr hdr;
	uint8_t text[];
};
#define PACKET_BUF_SIZE(size) ((size) + sizeof(struct packet))
#define PACKET_TEXT_SIZE(size) ((size) - sizeof(struct packet))
#define PACKET_TEXT(buf) ((buf) + offsetof(struct packet, text))
#define PACKET_HDR(buf) ((struct packethdr *)(buf))
struct packet_hshake_bstate {
	uint8_t ika[32];
	uint8_t eka[32];
	uint8_t ikb[32];
	uint8_t ikb_prv[32];
	uint8_t spkb[32];
	uint8_t spkb_prv[32];
	uint8_t opkb[32];
	uint8_t opkb_prv[32];
};
struct packet_hshake_cstate {
	uint8_t iskd[32];        /* daemon public identity (signing) key */
	uint8_t ikd[32];         /* daemon public identity (key-xchg) key */
	uint8_t iskc[32];        /* client public identity (signing) key */
	uint8_t iskc_prv[32];    /* client private identity (signing) key */
	uint8_t ikc[32];         /* client public identity (key-xchg) key */
	uint8_t ikc_prv[32];     /* client private identity (key-xchg) key */
	uint8_t ekc[32];         /* client public ephemeral (key-xchg) key */
	uint8_t ekc_prv[32];     /* client private ephemeral (key-xchg) key */
	uint8_t hkc[32];         /* client public hidden (key-xchg) key */
	uint8_t hkc_prv[32];     /* client private hidden (key-xchg) key */
	uint8_t cvc[32];         /* challenge value from client */
	uint8_t shared[32];      /* shared REPLY key */
};
struct packet_hshake_dstate {
	uint8_t iskd[32];        /* daemon public identity (signing) key */
	uint8_t iskd_prv[32];    /* daemon private identity (signing) key */
	uint8_t ikd[32];         /* daemon public identity (key-xchg) key */
	uint8_t ikd_prv[32];     /* daemon private identity (key-xchg) key */
	uint8_t ekd[32];         /* daemon public ephemeral (key-xchg) key */
	uint8_t ekd_prv[32];     /* daemon private ephemeral (key-xchg) key */
	uint8_t iskc[32];        /* client public identity (signing) key */
	uint8_t ikc[32];         /* client public identity (key-xchg) key */
	uint8_t ekc[32];         /* client public ephemeral (key-xchg) key */
	uint8_t cvd[32];         /* challenge value from daemon */
	uint8_t cvc[32];         /* challenge value from client */
	uint8_t shared[32];      /* shared REPLY key */
};
struct packet_ratchet_state_common {
	uint8_t dhkr[32];        /* public (DH) ratchet key (recv) */
	uint8_t dhks[32];        /* public (DH) ratchet key (send) */
	uint8_t dhks_prv[32];    /* private (DH) ratchet key (send) */
	uint8_t rk[32];          /* root key */
	uint8_t cks[32];         /* chain key (send) */
	uint8_t ckr[32];         /* chain key (recv) */
	uint8_t hks[32];         /* header key (send) */
	uint8_t hkr[32];         /* header key (recv) */
	uint8_t nhks[32];        /* next header key (send) */
	uint8_t nhkr[32];        /* next header key (recv) */
	uint8_t ad[64];          /* associated data */
	uint8_t cv[32];          /* challenge value */
	uint32_t ns;             /* message sequence number (send) */
	uint32_t nr;             /* message sequence number (recv) */
	uint32_t pn;             /* previous sending chain length */
	int prerecv;             /* are we in a pre-receive state? */
	struct packetkey_bucket *skipped; /* LL of buckets for missed keys */
	struct packetkey_bucket *spare_buckets;  /* pools for these so we don't */
	struct packetkey        *spare_packetkeys; /* need to constantly realloc  */
};                                             /* them.  we DO need to wipe!  */
struct packet_ratchet_state {
	struct packet_ratchet_state_common rac;
};
struct packet_ratchet_dstate {
	struct packet_ratchet_state_common rac;
	uint8_t iskc[32];
};
struct packet_ratchet_astate_prerecv {
	struct packet_ratchet_state_common rac;
	uint8_t hk[32];
	uint8_t ika[32];
	uint8_t eka[32];
	uint8_t spkb[32];
	uint8_t opkb[32];
};
union packet_state {
	struct packet_hshake_bstate hsb;
	struct packet_hshake_cstate hsc;
	struct packet_hshake_dstate hsd;
	struct packet_ratchet_state ra;
	struct packet_ratchet_dstate rad;
	struct packet_ratchet_astate_prerecv rap;
};
struct hshake_hello_msg {
	uint8_t hidden[32];
	uint8_t mac[16];
	uint8_t iskc[32];    /* client's long-term key-signing (identity) key */
	uint8_t ekc[32];     /* client's ephemeral key-exchange key */
	uint8_t cvc[32];     /* client's challenge value */
};
struct hshake_reply_msg {
	uint8_t mac[16];
	uint8_t eks[32];     /* server's ephemeral key-exchange key */
	uint8_t cvs[32];     /* server's challenge value */
};
struct hshake_ohello_msg {
	uint8_t mac[16];
	uint8_t nonce[24];
	uint8_t msgtype;
	uint8_t eka[32];
	uint8_t spkb[32];
	uint8_t opkb[32];
	uint8_t message_size[2];
	uint8_t message[];
};
struct hshake_omsg_msg {
	uint8_t msgtype;
	uint8_t message[];
};
#define PACKET_OHELLO_TEXT(buf) ((buf) + offsetof(struct hshake_ohello_msg, message))
#define PACKET_HELLO_SIZE sizeof(struct hshake_hello_msg)
#define PACKET_REPLY_SIZE sizeof(struct hshake_reply_msg)
#define PACKET_P2PHELLO_SIZE(n) (sizeof(struct hshake_ohello_msg) + (n))
/* PACKET_HSHAKE_SIZE = MAX( PACKET_{HELLO,REPLY}_SIZE ) */
#define PACKET_HSHAKE_SIZE PACKET_HELLO_SIZE
extern void packet_get_iskc(uint8_t iskc[32], const union packet_state *state);
extern int packet_hshake_aprepare(union packet_state *state,
	const uint8_t kex_public_key[32], const uint8_t kex_private_key[32],
	const uint8_t his_sign_public_key[32], const uint8_t his_public_key[32],
	const uint8_t his_signed_prekey[32], const uint8_t his_signed_prekey_sig[64],
	const uint8_t his_onetime_prekey[32]);
extern void packet_hshake_ahello(union packet_state *state, uint8_t *buf, size_t msgsize);
extern void packet_hshake_bprepare(union packet_state *state,
	const uint8_t her_kex_public_key[32], const uint8_t her_ephemeral_key[32],
	const uint8_t kex_public_key[32], const uint8_t kex_private_key[32],
	const uint8_t signed_prekey[32], const uint8_t signed_prekey_private[32],
	const uint8_t onetime_prekey[32], const uint8_t onetime_prekey_private[32]);
extern int packet_hshake_bfinish(union packet_state *state, uint8_t *buf, size_t size);
extern void packet_hshake_cprepare(union packet_state *state,
	const uint8_t his_sign_public_key[32], const uint8_t his_kex_public_key[32],
	const uint8_t sign_public_key[32], const uint8_t sign_private_key[32],
	const uint8_t kex_public_key[32], const uint8_t kex_private_key[32],
	const uint8_t client_challenge_value[32]);
extern void packet_hshake_chello(union packet_state *state, uint8_t buf[PACKET_HELLO_SIZE]);
extern int packet_hshake_cfinish(union packet_state *state, uint8_t buf[PACKET_REPLY_SIZE]);
extern void packet_hshake_dprepare(union packet_state *state,
	const uint8_t sign_public_key[32], const uint8_t sign_private_key[32],
	const uint8_t kex_public_key[32], const uint8_t kex_private_key[32],
	const uint8_t server_challenge_value[32]);
extern int packet_hshake_dcheck(union packet_state *state, uint8_t buf[PACKET_HELLO_SIZE]);
extern void packet_hshake_dreply(union packet_state *state, uint8_t buf[PACKET_REPLY_SIZE]);
extern void packet_lock(union packet_state *state, uint8_t *buf, size_t text_size);
extern int packet_unlock(union packet_state *state, uint8_t *buf, size_t buf_size);
extern size_t send_ohello_message(union packet_state *state,
	union packet_state *p2pstate, uint8_t recipient[32], uint8_t *buf,
	const uint8_t *text, size_t text_size);
extern size_t send_omsg_message(union packet_state *state,
	union packet_state *p2pstate, uint8_t recipient[32], uint8_t *buf,
	const uint8_t *text, size_t text_size);
extern size_t send_message(union packet_state *state,
	union packet_state *p2pstate, uint8_t recipient[32], uint8_t *buf,
	const uint8_t *text, size_t text_size);
extern size_t padme_enc(size_t l);
