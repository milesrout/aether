struct mesghdr {
	uint8_t hdrmac[16];
	uint8_t nonce[24];
	uint8_t msn[4];
	uint8_t pn[4];
	uint8_t pk[32];
	uint8_t mac[16];
};
struct mesg {
	struct mesghdr hdr;
	uint8_t text[];
};
struct mesg_hshake_cstate {
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
struct mesg_hshake_dstate {
	uint8_t iskd[32];        /* daemon public identity (signing) key */
	uint8_t iskd_prv[32];    /* daemon private identity (signing) key */
	uint8_t ikd[32];         /* daemon public identity (key-xchg) key */
	uint8_t ikd_prv[32];     /* daemon private identity (key-xchg) key */
	uint8_t ekd[32];         /* daemon public ephemeral (key-xchg) key */
	uint8_t ekd_prv[32];     /* daemon private ephemeral (key-xchg) key */
	uint8_t ikc[32];         /* client public identity (key-xchg) key */
	uint8_t ekc[32];         /* client public ephemeral (key-xchg) key */
	uint8_t cvd[32];         /* challenge value from daemon */
	uint8_t cvc[32];         /* challenge value from client */
	uint8_t shared[32];      /* shared REPLY key */
};
struct mesg_ratchet_state {
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
	struct mesgkey_bucket *skipped; /* LL of buckets for missed keys */
	struct mesgkey_bucket *spare_buckets;  /* pools for these so we don't */
	struct mesgkey        *spare_mesgkeys; /* need to constantly realloc  */
};                                             /* them.  we DO need to wipe!  */
struct mesg_state {
	union {
		struct mesg_hshake_cstate hsc;
		struct mesg_hshake_dstate hsd;
		struct mesg_ratchet_state ra;
	} u;
};
struct hshake_hello_msg {
	uint8_t hidden[32];
	uint8_t mac[16];
	uint8_t iskc[32];    /* client's long-term key-signing (identity) key */
	uint8_t ikc[32];     /* client's long-term key-exchng. (identity) key */
	uint8_t ekc[32];     /* client's ephemeral key-exchange key */
	uint8_t cvc[32];     /* client's challenge value */
	uint8_t ikc_sig[64]; /* signed by iskc */
	uint8_t ekc_sig[64]; /* signed by iskc */
};
struct hshake_reply_msg {
	uint8_t mac[16];
	uint8_t eks[32];     /* server's ephemeral key-exchange key */
	uint8_t eks_sig[64]; /* signed by iskd */
	uint8_t cvc_sig[64]; /* signed by iskd */
	uint8_t cvs[32];     /* server's challenge value */
};
extern int mesg_example1(int fd);
extern int mesg_example2(int fd);
#define MESG_HELLO_SIZE sizeof(struct hshake_hello_msg)
#define MESG_REPLY_SIZE sizeof(struct hshake_reply_msg)
/* MESG_HSHAKE_SIZE = MAX( MESG_{HELLO,REPLY}_SIZE ) */
#define MESG_HSHAKE_SIZE MESG_HELLO_SIZE
extern void mesg_hshake_cprepare(struct mesg_state *state,
	const uint8_t his_sign_public_key[32], const uint8_t his_kex_public_key[32],
	const uint8_t sign_public_key[32], const uint8_t sign_private_key[32],
	const uint8_t kex_public_key[32], const uint8_t kex_private_key[32]);
extern void mesg_hshake_chello(struct mesg_state *state, uint8_t buf[MESG_HELLO_SIZE]);
extern int mesg_hshake_cfinish(struct mesg_state *state, uint8_t buf[MESG_REPLY_SIZE]);
extern void mesg_hshake_dprepare(struct mesg_state *state,
	const uint8_t sign_public_key[32], const uint8_t sign_private_key[32],
	const uint8_t kex_public_key[32], const uint8_t kex_private_key[32]);
extern int mesg_hshake_dcheck(struct mesg_state *state, uint8_t buf[MESG_HELLO_SIZE]);
extern void mesg_hshake_dreply(struct mesg_state *state, uint8_t buf[MESG_REPLY_SIZE]);
#define MESG_BUF_SIZE(size) ((size) + sizeof(struct mesg))
#define MESG_TEXT_SIZE(size) ((size) - sizeof(struct mesg))
#define MESG_TEXT(buf) ((buf) + offsetof(struct mesg, text))
extern void mesg_lock(struct mesg_state *state, uint8_t *buf, size_t text_size);
extern int mesg_unlock(struct mesg_state *state, uint8_t *buf, size_t buf_size);
