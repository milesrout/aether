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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#include "monocypher.h"
#include "hkdf.h"

#define MAX_SKIP 1000

/* A note on terminology.
 *
 * I have tried to use terminology that is as consistent as possible.  Alas, I
 * have not always succeeded.  Here are some terms that might seem like
 * synonyms that I have tried to consistently distinguish:
 *
 * private key: exclusively refers to the _unshared_ half of an asymmetric keypair.
 * vs.
 * secret key: exclusively refers to _shared_ secret keys.
 */

/* types */
struct cs_state {
	uint32_t ns;             /* message sequence number (send) */
	uint32_t nr;             /* message sequence number (recv) */
	uint32_t pn;             /* previous sending chain length */
	uint8_t dhkr[32];        /* their public diffie-hellman key (recv) */
	uint8_t dhks[32];        /* our public diffie-hellman key (send) */
	uint8_t dhks_prv[32];    /* our private diffie-hellman key (send) */
	uint8_t rok[32];         /* root key */
	uint8_t sek[32];         /* sending chain key */
	uint8_t rek[32];         /* receiving chain key */
	uint8_t hks[32];         /* header key (send) */
	uint8_t nhks[32];        /* next header key (send) */
	uint8_t hkr[32];         /* header key (recv) */
	uint8_t nhkr[32];        /* next header key (recv) */
	uint8_t ad[64];          /* associated data */
	size_t ad_size;          /* associated data size */
	struct mesgkey_bucket *skipped;  /* LL of buckets for missed keys */
	struct mesgkey_bucket *spare_buckets;  /* pools for these so we don't */
	struct mesgkey        *spare_mesgkeys; /* need to constantly realloc  */
};                                             /* them.  we DO need to wipe!   */

struct mesgkey_bucket {
	uint8_t hk[32];
	struct mesgkey *first;
	struct mesgkey_bucket *next;
};

struct mesgkey {
	uint32_t msn;
	uint8_t mk[32];
	struct mesgkey *next;
};

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

/* debugging */
static void printhexbytes(const uint8_t *data, size_t size);
static void displaykey(const char *name, const uint8_t *key, size_t size);

/* real functions */
static void randbytes(uint8_t *data, size_t size);

static void generate_kex_keypair(uint8_t public_key[32], uint8_t private_key[32]);
static void generate_sig_keypair(uint8_t public_key[32], uint8_t private_key[32]);
static void compute_shared_secrets(uint8_t *sk, uint8_t *nhk, uint8_t *hk, uint8_t *dh);
static void cs_symm_ratchet(uint8_t mk[32], uint8_t ckn[32]);
static void cs_dh_ratchet(uint8_t rk[32], uint8_t ckn[32], uint8_t nhk[32], uint8_t dh[32]);

static int setclientup(const char *addr, const char *port);

static int try_decrypt_header(const struct cs_state *state, uint8_t hk[32], struct mesghdr *hdr);
static int try_skipped_message_keys(struct cs_state *state, struct mesg *mesg, size_t mesg_size);
static void skip_message_keys(struct cs_state *state, uint32_t until);
static void skip_message_keys_helper(struct cs_state *state, uint32_t until);
static int mesg_try_unlock(struct cs_state *state, struct mesg *mesg, size_t mesg_size);
static int mesg_unlock(uint8_t mk[32], struct mesg *mesg, size_t mesg_size, const uint8_t *ad, size_t ad_size);
static void mesg_lock(struct cs_state *state, struct mesg *mesg, size_t mesg_size);

static void safe_write(int fd, const uint8_t *buf, size_t size);
static size_t safe_read(int fd, uint8_t *buf, size_t size);

static
void
printhexbytes(const uint8_t *data, size_t size)
{
	while (size--) {
		fprintf(stderr, "%02x", *data++);
	}
}

static
void
displaykey(const char *name, const uint8_t *key, size_t size)
{
	printf("%s:\n", name);
	printhexbytes(key, size);
	putchar('\n');
}

static
void
randbytes(uint8_t *data, size_t size)
{
	ssize_t result, ssize = size;

	do result = getrandom(data, size, 0);
	while (ssize != result);
}

/* BEGIN: these are derived from monocypher directly */
static
void
store32_le(uint8_t out[4], uint32_t in)
{
    out[0] = (uint8_t)( in        & 0xff);
    out[1] = (uint8_t)((in >>  8) & 0xff);
    out[2] = (uint8_t)((in >> 16) & 0xff);
    out[3] = (uint8_t)((in >> 24) & 0xff);
}

static
uint32_t
load32_le(const uint8_t s[4])
{
    return (uint32_t)s[0]
        | ((uint32_t)s[1] <<  8)
        | ((uint32_t)s[2] << 16)
        | ((uint32_t)s[3] << 24);
}
/* END: these are derived from monocypher directly */

static
void
generate_kex_keypair(uint8_t public_key[32], uint8_t private_key[32])
{
	randbytes(private_key, 32);
	crypto_key_exchange_public_key(public_key, private_key);
}

static
void
generate_sig_keypair(uint8_t public_key[32], uint8_t private_key[32])
{
	randbytes(private_key, 32);
	crypto_sign_public_key(public_key, private_key);
}

static
int
check_key(const uint8_t isk[32], const char name[4], const uint8_t key[32], const uint8_t sig[64])
{
	uint8_t msg[36] = { 0 };
	int result;

	memcpy(msg, name, 4);
	memcpy(msg + 4, key, 32);
	result = crypto_check(sig, isk, msg, 36);
	crypto_wipe(msg, 36);

	return result;
}

static
void
sign_key(uint8_t sig[64],
	const uint8_t isk_prv[32], const uint8_t isk[32],
	const char name[4], const uint8_t key[32])
{
	uint8_t msg[36] = { 0 };

	memcpy(msg, name, 4);
	memcpy(msg + 4, key, 32);
	crypto_sign(sig, isk_prv, isk, msg, 36);
	crypto_wipe(msg, 36);
}


/* prepares the message by advancing the state machine, preparing the header,
 * encryping the message in place and then encrypting the header in place.
 * the resulting struct mesg is ready to be sent over the wire.
 *
 * mesg must point to the message to be prepared. if anything is to be done to
 * the message before it is sent (e.g. padding) it should be done before
 * calling this function.
 *
 * this function either fills in all those values or securely wipes the message
 * and all those buffer positions.
 *
 * pre-encryption, a message is:
   - a message sequence number (msn),
   - the number of messages in the previous sending chain (pn),
   - our ratchet public key (pk),
   - plaintext (text),
 * post-content-encryption, a message is:
   - a message sequence number (msn),
   - the number of messages in the previous sending chain (pn),
   - our ratchet public key (pk),
   - a message authentication code (mac),
    (each message is sent using a one-use secret key, so AEAD does not need a nonce)
   - the ciphertext (text),
 * post-header-encryption, a message is:
   - a message authentication code (hdrmac),
   - a single-use nonce (nonce),
   - the header ciphertext (hdrtext), which is the following, AEAD-encrypted:
     - a message sequence number (msn),
     - the number of messages in the previous sending chain (pn),
     - our ratchet public key (pk),
     - the content's message authentication code (mac),
   - the content's ciphertext (text),
 */

static const uint8_t zero_nonce[24];
static const uint8_t missing_key[32];

/* attempt to decrypt the header of an encrypted message 
 * mesg should be a struct mesg that has NOT had its header decrypted
 * hdrmac: valid
 * nonce:  valid
 * msn:    encrypted
 * pn:     encrypted
 * pk:     encrypted
 * mac:    encrypted
 * text:   encrypted
 *
 * if the header was decrypted successfully, returns 0
 *       -> WITHOUT WIPING THE HEADER KEY. <-
 * otherwise returns -1;
 */
static
int
try_decrypt_header(const struct cs_state *state,
		uint8_t hk[32], struct mesghdr *hdr)
{
	int result;

	result = crypto_unlock_aead(
		hdr->msn,
		hk,
		hdr->nonce,
		hdr->hdrmac,
		state->ad,
		state->ad_size,
		hdr->msn,
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	return result;
}

static
int
try_skipped_message_keys(struct cs_state *state, struct mesg *mesg, size_t mesg_size)
{
	struct mesgkey_bucket *prev_bucket, *bucket;
	struct mesgkey *prev_mesgkey, *mesgkey;

	prev_bucket = NULL;
	bucket = state->skipped;

	while (bucket != NULL) {

		if (try_decrypt_header(state, bucket->hk, &mesg->hdr)) {
			goto outer_continue;
		}

		prev_mesgkey = NULL;
		mesgkey = bucket->first;

		while (mesgkey != NULL) {

			if (mesgkey->msn != load32_le(mesg->hdr.msn)) {
				goto inner_continue;
			}

			/* header decrypted and the correct msn */

			/* attempt to decrypt the message */
			if (mesg_unlock(mesgkey->mk,
					mesg, mesg_size,
					state->ad, state->ad_size))
				return -1;

			/* if successful, remove the struct mesgkey from the
			 * bucket and remove the bucket from the bucket list if
			 * it is now empty.
			 */
			
			if (prev_mesgkey != NULL) {
				prev_mesgkey->next = mesgkey->next;
				goto detach_mesgkey;
			}

			if (mesgkey->next != NULL) {
				bucket->first = mesgkey->next;
				goto detach_mesgkey;
			}

			if (prev_bucket != NULL) {
				prev_bucket->next = bucket->next;
				goto detach_bucket;
			}

			if (bucket->next != NULL) {
				state->skipped = bucket->next;
				goto detach_bucket;
			}

		detach_bucket:
			crypto_wipe(bucket, sizeof(struct mesgkey_bucket));
			bucket->next = state->spare_buckets;
			state->spare_buckets = bucket;
		detach_mesgkey:
			crypto_wipe(mesgkey, sizeof(struct mesgkey));
			mesgkey->next = state->spare_mesgkeys;
			state->spare_mesgkeys = mesgkey;
			return 0;

		inner_continue:
			prev_mesgkey = mesgkey;
			mesgkey = mesgkey->next;
		}
	outer_continue:
		prev_bucket = bucket;
		bucket = bucket->next;
	}

	return -1;
}

static
struct mesgkey_bucket *
bucket_create(struct cs_state *state)
{
	struct mesgkey_bucket *b;

	if (NULL != (b = state->spare_buckets)) {
		state->spare_buckets = b->next;
		return b;
	}

	return malloc(sizeof *b);
}

static
struct mesgkey *
mesgkey_create(struct cs_state *state)
{
	struct mesgkey *m;

	if (NULL != (m = state->spare_mesgkeys)) {
		state->spare_mesgkeys = m->next;
		return m;
	}

	return malloc(sizeof *m);
}

static
void
skip_message_keys(struct cs_state *state, uint32_t until)
{
	if (MAX_SKIP == 0)
		return;

	if (until >= (MAX_SKIP + 1) && state->nr >= until - (MAX_SKIP + 1)) {
		/* TODO: error handling */
		fprintf(stderr, "Too many messages to skip. Abort.\n");
		exit(EXIT_FAILURE);
	}

	if (!crypto_verify32(state->rek, missing_key) || state->nr >= until) {
		return;
	}

	skip_message_keys_helper(state, until);
}

static
void
skip_message_keys_helper(struct cs_state *state, uint32_t until)
{
	struct mesgkey *prev_mesgkey = NULL;
	struct mesgkey_bucket *bucket = bucket_create(state);

	memcpy(bucket->hk, state->hkr, 32);
	bucket->next = state->skipped;
	state->skipped = bucket;

	while (state->nr < until) {
		struct mesgkey *mesgkey = mesgkey_create(state);

		if (prev_mesgkey == NULL)
			bucket->first = mesgkey;
		else
			prev_mesgkey->next = mesgkey;
		prev_mesgkey = mesgkey;

		mesgkey->msn = state->nr;
		cs_symm_ratchet(mesgkey->mk, state->rek);
		mesgkey->next = NULL;

		state->nr++;
	}
}

static
void
step_receiver_ratchet(struct cs_state *state, struct mesghdr *hdr)
{
	uint8_t dh[32];

	state->pn = state->ns;
	state->ns = 0;
	state->nr = 0;

	memcpy(state->hks, state->nhks, 32);
	memcpy(state->hkr, state->nhkr, 32);

	memcpy(state->dhkr, hdr->pk, 32);

	crypto_key_exchange(dh, state->dhks_prv, state->dhkr);
	cs_dh_ratchet(state->rok, state->rek, state->nhkr, dh);

	generate_kex_keypair(state->dhks, state->dhks_prv);
	crypto_key_exchange(dh, state->dhks_prv, state->dhkr);
	cs_dh_ratchet(state->rok, state->sek, state->nhks, dh);

	crypto_wipe(dh, 32);
}

static
int
mesg_try_unlock(struct cs_state *state, struct mesg *mesg, size_t mesg_size)
{
	uint8_t mk[32];
	int result;

	if (!try_skipped_message_keys(state, mesg, mesg_size)) {
		return 0;
	}

	if (try_decrypt_header(state, state->hkr, &mesg->hdr)) {
		if (try_decrypt_header(state, state->nhkr, &mesg->hdr)) {
			return -1;
		}
		skip_message_keys(state, load32_le(mesg->hdr.pn));
		step_receiver_ratchet(state, &mesg->hdr);
	}
	skip_message_keys(state, load32_le(mesg->hdr.msn));

	cs_symm_ratchet(mk, state->rek);
	state->nr++;

	result = mesg_unlock(mk, mesg, mesg_size, state->ad, state->ad_size);
	crypto_wipe(mk, 32);
	return result;
}

/* decrypt a partially decrypted message 
 * mesg should be a struct mesg that has had its header decrypted
 * hdrmac: should have been wiped already
 * nonce:  should have been wiped already
 * msn:    valid
 * pn:     valid
 * pk:     valid
 * mac:    valid
 * text:   encrypted
 *
 * if the message was decrypted successfully, wipes mk and returns 0.
 * otherwise returns -1;
 */
static
int
mesg_unlock(uint8_t mk[32], struct mesg *mesg, size_t mesg_size,
		const uint8_t *ad, size_t ad_size)
{
	int result;

	result = crypto_unlock_aead(
		mesg->text,
		mk,
		zero_nonce,
		mesg->hdr.mac,
		ad,
		ad_size,
		mesg->text,
		mesg_size);

	if (result == 0) {
		crypto_wipe(mk, 32);
	}

	return result;
}

static
void
mesg_lock(struct cs_state *state, struct mesg *mesg, size_t mesg_size)
{
	uint8_t mk[32];

	cs_symm_ratchet(mk, state->sek);

	store32_le(mesg->hdr.msn, state->ns);
	store32_le(mesg->hdr.pn, state->pn);
	memcpy(mesg->hdr.pk, state->dhks, 32);

	crypto_lock_aead(
		mesg->hdr.mac,
		mesg->text,
		mk,
		zero_nonce, /* (each message is sent using a one-use secret key,
		                so AEAD can use a constant nonce)
			       (perhaps this should be some other constant to 
				provide domain separation?)*/
		state->ad,
		state->ad_size,
		mesg->text,
		mesg_size);

	randbytes(mesg->hdr.nonce, 24);

	crypto_lock_aead(
		mesg->hdr.hdrmac,
		mesg->hdr.msn,
		state->hks,
		mesg->hdr.nonce,
		state->ad,
		state->ad_size,
		mesg->hdr.msn,
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	crypto_wipe(mk, 32);

	state->ns++;
}

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

struct dh_init_msg {
	uint8_t iskc[32];    /* client's long-term key-signing (identity) key */
	uint8_t ikc[32];     /* client's long-term key-exchng. (identity) key */
	uint8_t ekc[32];     /* client's ephemeral key-exchange key */
	uint8_t ikc_sig[64]; /* signature of ikc by iskc */
	uint8_t ekc_sig[64]; /* signature of ekc by iskc */
	uint8_t cvc[32];     /* client's challenge value */
};

/* this message is sent assuming that the client knows isks, the server's
 * long-term key-signing (identity) key.
 */
struct dh_serv_msg {
	uint8_t iks[32];     /* server's long-term key-exchange (identity) key */
	uint8_t eks[32];     /* server's ephemeral key-exchange key */
	uint8_t iks_sig[64]; /* signature of iks by isks */
	uint8_t eks_sig[64]; /* signature of eks by isks */
	uint8_t cvc_sig[64]; /* signature of cvc by isks */
	uint8_t cvs[32];     /* server's challenge value */
};

struct ra_init_msg {
	uint8_t ikc[32];     /* client's identity key */
};

static const uint8_t cs_hs_info[]   = "AetherwindClientServerHandshake";
static const uint8_t cs_symm_info[] = "AetherwindClientServerSymmetricRatchet";
static const uint8_t cs_dh_info[]   = "AetherwindClientServerDiffieHellmanRatchet";
static const uint8_t pp_hs_info[]   = "AetherwindPeerToPeerHandshake";
static const uint8_t pp_symm_info[] = "AetherwindPeerToPeerSymmetricRatchet";
static const uint8_t pp_dh_info[]   = "AetherwindPeerToPeerDiffieHellmanRatchet";

static
void
cs_symm_ratchet(uint8_t mk[32], uint8_t ckn[32])
{
	uint8_t tmp[64 + sizeof(cs_symm_info) + 1];

	hkdf_blake2b(
		tmp,          64,
		NULL,         0,
		cs_symm_info, sizeof(cs_symm_info),
		ckn,          32);

	memcpy(mk,  tmp,      32);
	memcpy(ckn, tmp + 32, 32);

	crypto_wipe(tmp, 64);
}

static
void
cs_dh_ratchet(uint8_t rk[32], uint8_t ck[32], uint8_t nhk[32], uint8_t dh[32])
{
	uint8_t tmp[96 + sizeof(cs_dh_info) + 1];

	hkdf_blake2b(
		tmp,        96,
		rk,         32,
		cs_dh_info, sizeof(cs_dh_info),
		dh,         32);

	memcpy(rk,  tmp,      32);
	memcpy(ck,  tmp + 32, 32);
	memcpy(nhk, tmp + 64, 32);

	crypto_wipe(dh, 32);
	crypto_wipe(tmp, 96);
}

static
void
compute_shared_secrets(uint8_t sk[32], uint8_t nhk[32], uint8_t hk[32],
		uint8_t dh[128])
{
	uint8_t tmp[96 + sizeof(cs_hs_info) + 1];

	hkdf_blake2b(
		tmp,        96,
		NULL,       0,
		cs_hs_info, sizeof(cs_hs_info),
		dh,         128);

	memcpy(sk,  tmp,      32);
	memcpy(hk,  tmp + 32, 32);
	memcpy(nhk, tmp + 64, 32);

	crypto_wipe(dh, 128);
	crypto_wipe(tmp, 96);
}

union mesgbuf {
	uint8_t buf[65536];
	struct mesg mesg;
};
#define MESGBUF_SIZE(text_size) (sizeof(struct mesg) + (text_size))

static
void
client(const char *addr, const char *port)
{
	struct dh_init_msg initmsg;
	struct dh_serv_msg *servmsg;
	int fd;
	ssize_t nread;
	uint8_t iskc[32], iskc_prv[32];
	uint8_t ikc[32], ikc_prv[32], ikc_sig[64];
	/* TODO: discover through DNS or HTTPS or something */
	/* uint8_t isks[32]; */
	uint8_t ekc[32], ekc_prv[32];
	uint8_t cvc[32];
	uint8_t dh[128];
	uint8_t *dh1 = dh, *dh2 = dh + 32;
	uint8_t *dh3 = dh + 64, *dh4 = dh + 96;
	uint8_t hk[32], nhk[32], sk[32];
	uint8_t iks[32], eks[32];
	struct cs_state state;

	memset(&initmsg, 0, sizeof initmsg);

	generate_sig_keypair(iskc, iskc_prv);

	generate_kex_keypair(ikc, ikc_prv);

	sign_key(ikc_sig, iskc_prv, iskc, "AECI", ikc);

	fd = setclientup(addr, port);

	generate_kex_keypair(ekc, ekc_prv);

	randbytes(cvc, 32);

	memcpy(initmsg.iskc,    iskc,    32);
	memcpy(initmsg.ikc,     ikc,     32);
	memcpy(initmsg.ekc,     ekc,     32);
	memcpy(initmsg.ikc_sig, ikc_sig, 64);
	memcpy(initmsg.cvc,     cvc,     32);
	sign_key(initmsg.ekc_sig, iskc_prv, iskc, "AECE", ekc);

	safe_write(fd, (const uint8_t *)&initmsg, sizeof initmsg);
	crypto_wipe((uint8_t *)&initmsg, sizeof initmsg);

	{
		uint8_t buf[65536];
		nread = safe_read(fd, buf, 65536);
		if (nread != sizeof(struct dh_serv_msg)) {
			fprintf(stderr, "Received the wrong message.\n");
			goto fail; /* skips crypto_wipe */
		}

		servmsg = (struct dh_serv_msg *)buf;
		if (check_key(isks, "AESI", servmsg->iks, servmsg->iks_sig)) {
			fprintf(stderr, "AESI Key failed signature check!\n");
			goto fail; /* skips crypto_wipe */
		}
		if (check_key(isks, "AESE", servmsg->eks, servmsg->eks_sig)) {
			fprintf(stderr, "AESE Key failed signature check!\n");
			goto fail; /* skips crypto_wipe */
		}
		if (check_key(isks, "AESC", cvc, servmsg->cvc_sig)) {
			fprintf(stderr, "AESC Key failed signature check!\n");
			goto fail; /* skips crypto_wipe */
		}

		memcpy(iks, servmsg->iks, 32);
		memcpy(eks, servmsg->eks, 32);

		crypto_key_exchange(dh1, ikc_prv, iks);
		crypto_key_exchange(dh2, ekc_prv, iks);
		crypto_key_exchange(dh3, ikc_prv, eks);
		crypto_key_exchange(dh4, ekc_prv, eks);
		compute_shared_secrets(sk, nhk, hk, dh);

		/* Is this correct ? */
		crypto_wipe(ekc_prv, 32);
		crypto_wipe(ekc, 32);
		crypto_wipe(servmsg, sizeof *servmsg);
	}

	{
		uint8_t dh5[32];

		memset(&state, 0, sizeof(struct cs_state));
		generate_kex_keypair(state.dhks, state.dhks_prv);
		state.ad_size = 64;
		memcpy(state.ad,       ikc,     32);
		memcpy(state.ad + 32,  iks,     32);
		memcpy(state.hks,      hk,      32);
		memcpy(state.nhkr,     nhk,     32);
		memcpy(state.rok,      sk,      32);

		crypto_key_exchange(dh5, state.dhks_prv, eks);
		crypto_wipe(eks, 32);
		cs_dh_ratchet(state.rok, state.sek, state.nhks, dh5);
		crypto_wipe(dh5, 32);

		{
			union mesgbuf mesgbuf;
			union mesgbuf mesgbuf2;
			union mesgbuf mesgbuf3;

			memset(mesgbuf.mesg.text, 0x55, 256);
			mesg_lock(&state, &mesgbuf.mesg, 256);
			memset(mesgbuf2.mesg.text, 0x77, 256);
			mesg_lock(&state, &mesgbuf2.mesg, 256);
			memset(mesgbuf3.mesg.text, 0x99, 256);
			mesg_lock(&state, &mesgbuf3.mesg, 256);
			safe_write(fd, mesgbuf3.buf, MESGBUF_SIZE(256));
			safe_write(fd, mesgbuf2.buf, MESGBUF_SIZE(256));
			safe_write(fd, mesgbuf.buf, MESGBUF_SIZE(256));
		}
	}

fail:
	/* TODO: make sure absolutely everything is wiped here */
	exit(EXIT_FAILURE);
}

/* the following functions are "safe" in the sense that instead of returning an
 * error, they abort the program.  They are not safe in the sense that they
 * cannot produce errors or in the sense that they can be used with impunity.
 */
static
size_t
safe_read(int fd, uint8_t *buf, size_t max_size_p1)
{
	ssize_t nread;

	do nread = read(fd, buf, max_size_p1);
	while (nread == -1 && errno == EINTR);

	if (nread == -1) {
		fprintf(stderr, "Error while reading from socket.\n");
		exit(EXIT_FAILURE);
	}
	if ((size_t)nread == max_size_p1) {
		fprintf(stderr, "Peer sent a packet that is too large.\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

static
size_t
safe_recvfrom(int fd, uint8_t *buf, size_t max_size_p1,
		struct sockaddr_storage *peeraddr, socklen_t *peeraddr_len)
{
	ssize_t nread;

	do {
		*peeraddr_len = sizeof(peeraddr);
		nread = recvfrom(fd, buf, max_size_p1, 0,
			(struct sockaddr *)peeraddr, peeraddr_len);
	} while (nread == -1 && errno == EINTR);

	if (nread == -1) {
		fprintf(stderr, "Error while reading from socket.\n");
		exit(EXIT_FAILURE);
	}
	if ((size_t)nread == max_size_p1) {
		fprintf(stderr, "Peer sent a packet that is too large.\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

static
void
safe_write(int fd, const uint8_t *buf, size_t size)
{
	ssize_t result;

	result = write(fd, buf, size);
	while (result == -1 || (size_t)result < size) {
		if (result == -1 && errno == EINTR) {
			result = write(fd, buf, size);
			continue;
		}
		if (result == -1) {
			fprintf(stderr, "Error while writing to socket.\n");
			exit(EXIT_FAILURE);
		}
		buf += result;
		size -= result;
		result = write(fd, buf, size);
	}
}

static
void
safe_sendto(int fd, const uint8_t *buf, size_t size, struct sockaddr *peeraddr, socklen_t peeraddr_len)
{
	ssize_t result;

	result = sendto(fd, buf, size, 0, peeraddr, peeraddr_len);
	while (result == -1 || (size_t)result < size) {
		if (result == -1 && errno == EINTR) {
			result = sendto(fd, buf, size, 0, peeraddr, peeraddr_len);
			continue;
		}
		if (result == -1) {
			fprintf(stderr, "Error while writing to socket.\n");
			exit(EXIT_FAILURE);
		}
		buf += result;
		size -= result;
		result = sendto(fd, buf, size, 0, peeraddr, peeraddr_len);
	}
}

static
int
setclientup(const char *addr, const char *port)
{
	struct addrinfo hints, *result, *rp;
	int fd = -1, gai;
	/*
	ssize_t nread;
	char buf[128];
	*/

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	gai = getaddrinfo(addr, port, &hints, &result);
	if (gai != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		exit(EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			return fd;

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		fprintf(stderr, "Couldn't bind to socket.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Couldn't connect to %s on port %s.\n", addr, port);
	exit(EXIT_FAILURE);

	/*
	for (;;) {
		nread = write(fd, buf, 128);
		if (nread == 128)
			continue;

		fprintf(stderr, "Received %zd bytes.\n", nread);
	}
	*/
}

static
void
serve(const char *addr, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int fd = -1;
	int gai;
	struct sockaddr_storage peeraddr;
	socklen_t peeraddr_len;
	ssize_t nread;
	uint8_t buf[65536];
	uint8_t iks[32], iks_prv[32];
	uint8_t ikc[32];
	struct cs_state state;

	generate_kex_keypair(iks, iks_prv);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	gai = getaddrinfo(addr, port, &hints, &result);
	if (gai != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		exit(EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		fprintf(stderr, "Couldn't bind to socket.\n");
		exit(EXIT_FAILURE);
	}

	for (;;) {
		peeraddr_len = sizeof(peeraddr);
		nread = safe_recvfrom(fd, buf, 65536,
			&peeraddr, &peeraddr_len);

		fprintf(stderr, "Received %zd bytes.\n", nread);
		if (nread == sizeof(struct dh_init_msg)) {
			struct dh_init_msg *initmsg = (struct dh_init_msg *)buf;
			struct dh_serv_msg servmsg;
			uint8_t cvs[32];
			uint8_t eks[32], eks_prv[32];
			uint8_t dh[128];
			uint8_t *dh1 = dh, *dh2 = dh + 32;
			uint8_t *dh3 = dh + 64, *dh4 = dh + 96;
			uint8_t hk[32], nhk[32], sk[32];

			putchar('\n');

			/* TODO: Proof of work - to prevent denial of service:
			 * The server should require that the client does some
			 * proof-of-work task in order to initiate a connection.
			 * This task should be both memory-hard and time-hard
			 * for the client but easy to verify for the server.
			 *
			 * The hardness of the task could be altered based on:
			 * - current server load
			 * - trustworthiness of the client (after identity
			 *   verification)
			 * - niceness of the client (how much they load the
			 *   server and how much they're loading the server at
			 *   the moment)
			 * - any other relevant factors
			 */

			if (check_key(initmsg->iskc, "AECI", initmsg->ikc, initmsg->ikc_sig)) {
				fprintf(stderr, "AECI Key failed signature check!\n");
				exit(EXIT_FAILURE);
			}
			if (check_key(initmsg->iskc, "AECE", initmsg->ekc, initmsg->ekc_sig)) {
				fprintf(stderr, "AECE Key failed signature check!\n");
				exit(EXIT_FAILURE);
			}

			generate_kex_keypair(eks, eks_prv);

			randbytes(cvs, 32);

			/* Signing iks only ever needs to be done once */
			memcpy(servmsg.iks, iks, 32);
			memcpy(servmsg.eks, eks, 32);
			sign_key(servmsg.iks_sig, isks_prv, isks, "AESI", iks);
			sign_key(servmsg.eks_sig, isks_prv, isks, "AESE", eks);
			sign_key(servmsg.cvc_sig, isks_prv, isks, "AESC", initmsg->cvc);
			memcpy(servmsg.cvs, cvs, 32);

			safe_sendto(fd, (const uint8_t *)&servmsg, sizeof servmsg,
				(struct sockaddr *)&peeraddr, peeraddr_len);
			crypto_wipe((uint8_t *)&servmsg, sizeof servmsg);

			crypto_key_exchange(dh1, iks_prv, initmsg->ikc);
			crypto_key_exchange(dh2, iks_prv, initmsg->ekc);
			crypto_key_exchange(dh3, eks_prv, initmsg->ikc);
			crypto_key_exchange(dh4, eks_prv, initmsg->ekc);

			compute_shared_secrets(sk, nhk, hk, dh);

			memcpy(ikc, initmsg->ikc, 32);
			crypto_wipe(initmsg, sizeof *initmsg);

			memset(&state, 0, sizeof(struct cs_state));
			state.ad_size = 64;
			memcpy(state.dhks,     eks,     32);
			memcpy(state.dhks_prv, eks_prv, 32);
			memcpy(state.rok,      sk,      32);
			memcpy(state.ad,       ikc,     32);
			memcpy(state.ad + 32,  iks,     32);
			memset(state.hks,      0,       32);
			memcpy(state.nhks,     nhk,     32);
			memset(state.hkr,      0,       32);
			memcpy(state.nhkr,     hk,      32);
#define MESG_SIZE 256
		} else if (nread == sizeof(struct mesg) + MESG_SIZE) {
			struct mesg *mesg = (struct mesg *)buf;

			if (mesg_try_unlock(&state, mesg, MESG_SIZE)) {
				fprintf(stderr, "Couldn't decrypt\n");
			} else {
				displaykey("plain", mesg->text, MESG_SIZE);
			}
#undef MESG_SIZE
		}
	}
}

static
void
usage(const char *prog)
{
	fprintf(stderr, "usage: %s HOST PORT (s[erve] | a[lice] | b[ob])\n", prog);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	const char *host, *port;

	if (argc != 4) 
		usage(argv[0]);

	host = argv[1];
	port = argv[2];

	switch (argv[3][0]) {
		case 's': serve(host, port); break;
		case 'c': client(host, port); break;
		default:  usage(argv[0]);
	}

	return 0;
}
