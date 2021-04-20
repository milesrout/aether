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

/* TODO: safe and portable load_* (for endianness, undef behaviour) */

#define MAX_SKIP 12
#define malloc(sz) (assert_malloc(sz))

static
void *
assert_malloc(size_t sz)
{
	void *p = malloc(sz);

	if (!p)
		system("\"$BROWSER\" 'ddg.gg?q=newegg+ram'");

	return p;
}

struct message {
	struct message *next;
	uint8_t header[128];
	uint8_t message[];
};

struct mailbox {
	uint8_t ik[32];
	uint8_t isk[32];
	struct message *msgs;
};

struct connection {
	uint8_t ikc[32]; /* client's identity key */
	uint8_t rok[32]; /* root key */
	uint8_t rek[32]; /* receiving chain key */
	uint8_t sek[32]; /* sending chain key */
};

/* 0: Alice, 1: Bob */
static struct mailbox mboxes[8] = { 0 };

/* debugging */
static void printhexbytes(const uint8_t *data, size_t size);
static void displaykey(const char *name, const uint8_t *key, size_t size);

/* real functions */
static void randbytes(uint8_t *data, size_t size);
static void generate_kex_keypair(uint8_t public_key[32], uint8_t secret_key[32]);
static void compute_shared_secrets(uint8_t *sk, uint8_t *nhk, uint8_t *hk, uint8_t *dh);
static void cs_symm_ratchet(uint8_t mk[32], uint8_t ckn[32]);
static void cs_dh_ratchet(uint8_t rk[32], uint8_t ckn[32], uint8_t nhk[32], uint8_t dh[32]);

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
	uint16_t attempts = 0;

	while (ssize != (result = getrandom(data, size, 0))) {
		/* intentionally empty (functionally) */
		if (attempts++ == 0) {
			fprintf(stderr, "getrandom loop\n");
			abort();
		}
	}
}

static
void
generate_kex_keypair(uint8_t public_key[32], uint8_t secret_key[32])
{
	randbytes(secret_key, 32);
	crypto_key_exchange_public_key(public_key, secret_key);
}

static
void
generate_sig_keypair(uint8_t *public_key, uint8_t *secret_key)
{
	randbytes(secret_key, 32);
	crypto_sign_public_key(public_key, secret_key);
}

static
void
alice_generate_keys(
	uint8_t *ika, uint8_t *eka, uint8_t *ika_prv, uint8_t *eka_prv)
{
	generate_kex_keypair(ika, ika_prv);
	displaykey("ika",     ika, 32);
	displaykey("ika.prv", ika_prv, 32);

	putchar('\n');

	generate_kex_keypair(eka, eka_prv);
	displaykey("eka",     eka, 32);
	displaykey("eka.prv", eka_prv, 32);
}

static
int
check_key(const uint8_t *isk, const char *name, const uint8_t *key, const uint8_t *sig)
{
	uint8_t msg[36] = { 0 };

	fprintf(stderr, "checking %s:\n", name);
	memcpy(msg, name, 4);
	memcpy(msg + 4, key, 32);
	displaykey("msg", msg, 36);
	displaykey("sig", sig, 64);

	return crypto_check(sig, isk, msg, 36);
}

static
void
sign_key(
	const uint8_t *isk_prv, const uint8_t *isk,
	const char *name, const uint8_t *key, uint8_t *sig)
{
	uint8_t msg[36] = { 0 };
	memcpy(msg, name, 4);
	memcpy(msg + 4, key, 32);
	crypto_sign(sig, isk_prv, isk, msg, 36);
	displaykey("msg", msg, 36);
	displaykey("sig", sig, 64);
}

static
void
bob_sign_keys(
	const uint8_t *iskb, const uint8_t *iskb_prv,
	const uint8_t *ikb, const uint8_t *spkb, const uint8_t *opkb,
	uint8_t *ikb_sig, uint8_t *spkb_sig, uint8_t *opkb_sig)
{
	sign_key(iskb_prv, iskb, "AEWI", ikb, ikb_sig);
	putchar('\n');
	sign_key(iskb_prv, iskb, "AEWS", spkb, spkb_sig);
	putchar('\n');
	sign_key(iskb_prv, iskb, "AEWO", opkb, opkb_sig);
}

static
void
bob_generate_keys(
	uint8_t *iskb, uint8_t *ikb, uint8_t *spkb, uint8_t *opkb,
	uint8_t *iskb_prv, uint8_t *ikb_prv, uint8_t *spkb_prv, uint8_t *opkb_prv)
{
	generate_sig_keypair(iskb, iskb_prv);
	displaykey("iskb",     iskb, 32);
	displaykey("iskb.prv", iskb_prv, 32);

	putchar('\n');

	generate_kex_keypair(ikb, ikb_prv);
	displaykey("ikb",     ikb, 32);
	displaykey("ikb.prv", ikb_prv, 32);

	putchar('\n');

	generate_kex_keypair(spkb, spkb_prv);
	displaykey("spkb",     spkb, 32);
	displaykey("spkb.prv", spkb_prv, 32);

	putchar('\n');

	generate_kex_keypair(opkb, opkb_prv);
	displaykey("opkb",     opkb, 32);
	displaykey("opkb.prv", opkb_prv, 32);
}

struct init_msg {
	uint8_t ik[32];
	uint8_t ek[32];
	uint8_t mac[16];
	uint8_t nonce[24];
	uint16_t text_size;
	uint8_t text[];
};

static
void
alice(struct init_msg **message,
		const uint8_t *ika,  const uint8_t *ika_prv,
		const uint8_t *eka,        uint8_t *eka_prv,
		const uint8_t *iskb,
		const uint8_t *ikb,  const uint8_t *ikb_sig,
		const uint8_t *spkb, const uint8_t *spkb_sig,
		const uint8_t *opkb, const uint8_t *opkb_sig)
{
	uint8_t dh[128];
	uint8_t *dh1 = dh, *dh2 = dh + 32, *dh3 = dh + 64, *dh4 = dh + 96;
	uint8_t sk[32];
	uint8_t ad[64];
	uint8_t mac[16];
	/*uint8_t text[] = "Hello, Bob! My name is Alice. How are you?";*/
	uint8_t text[] = "12345678123456781234567812345678";
	uint8_t nonce[24];
	uint16_t text_size = strlen((const char*)text);
	struct init_msg *msg;

	*message = NULL;

	/* TODO: update sizeof calculation when text changes */
	msg = malloc(sizeof *msg + sizeof(text));
	if (msg == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(EXIT_FAILURE);
	}

	/* TODO: verify signature */
	/* monocypher tells us not to use a key used for key exchange for 
	 * signing or encryption, yet that seems to be standard in X3DH.
	 * instead we will create a signing key and a key exchange key, and we
	 * will sign the identity key-exchange public key with the identity
	 * key-signing key, and also sign the "signed prekey" with the same
	 * key. so actually your identity key is really your identity key-
	 * -signing key, while your "identity (key-exchange) public key" isn't
	 * actually your root identity key at all but specifically your
	 * key-exchange identity key.  this means that people can actually
	 * change their (key-exchange) identity keys, right?
	 *
	 * ALSO: shouldn't the one-time keys be pre-signed by Bob?
	 */
	if (check_key(iskb, "AEWI", ikb, ikb_sig)) {
		fprintf(stderr, "AEWI Key failed signature check!\n");
		exit(EXIT_FAILURE);
	} else fprintf(stderr, "checked ikb\n\n");
	if (check_key(iskb, "AEWS", spkb, spkb_sig)) {
		fprintf(stderr, "AEWS Key failed signature check!\n");
		exit(EXIT_FAILURE);
	} else fprintf(stderr, "checked spkb\n\n");
	if (check_key(iskb, "AEWO", opkb, opkb_sig)) {
		fprintf(stderr, "AEWO Key failed signature check!\n");
		exit(EXIT_FAILURE);
	} else fprintf(stderr, "checked opkb\n\n");

	crypto_key_exchange(dh1, ika_prv, spkb);
	displaykey("dh1", dh1, 32);

	crypto_key_exchange(dh2, eka_prv, ikb);
	displaykey("dh2", dh2, 32);

	crypto_key_exchange(dh3, eka_prv, spkb);
	displaykey("dh3", dh3, 32);

	crypto_key_exchange(dh4, eka_prv, opkb);
	displaykey("dh4", dh4, 32);

	crypto_blake2b_general(sk, 32, NULL, 0, dh, 128);
	displaykey("sk", sk, 32);

	crypto_wipe(eka_prv, 32);
	crypto_wipe(dh, 128);

	memcpy(ad, ika, 32);
	memcpy(ad + 32, ikb, 32);

	randbytes(nonce, 24);
	displaykey("nonce", nonce, 24);

	putchar('\n');

	displaykey("plaintext", text, text_size);
	printf("%s\n", text);
	crypto_lock_aead(mac, text, sk, nonce, ad, 64, text, text_size);
	displaykey("ciphertext", text, text_size);

	memcpy(&msg->ik, ika, 32);
	memcpy(&msg->ek, eka, 32);
	memcpy(&msg->mac, mac, 16);
	memcpy(&msg->nonce, nonce, 24);
	msg->text_size = text_size;
	memcpy(&msg->text, text, text_size);

	displaykey("message", (uint8_t *)msg, 108 + text_size);

	*message = msg;
}

static
void
bob(const struct init_msg *msg, const uint8_t *ikb, const uint8_t *ikb_prv,
		uint8_t *spkb_prv, uint8_t *opkb_prv)
{
	uint8_t ika[32], eka[32];
	uint8_t dh[128];
	uint8_t *dh1 = dh, *dh2 = dh + 32, *dh3 = dh + 64, *dh4 = dh + 96;
	uint8_t sk[32];
	uint8_t ad[64];
	uint8_t mac[16];
	uint8_t text[65536] = { 0 };
	uint8_t nonce[24];
	int result;

	memcpy(ika, msg->ik, 32);
	displaykey("ika", ika, 32);

	memcpy(eka, msg->ek, 32);
	displaykey("eka", eka, 32);

	memcpy(mac, msg->mac, 16);
	displaykey("mac", mac, 16);

	memcpy(nonce, msg->nonce, 24);
	displaykey("nonce", nonce, 24);

	memcpy(text, msg->text, msg->text_size);
	displaykey("text", text, msg->text_size);

	putchar('\n');

	crypto_key_exchange(dh1, spkb_prv, ika);
	displaykey("dh1", dh1, 32);

	crypto_key_exchange(dh2, ikb_prv, eka);
	displaykey("dh2", dh2, 32);

	crypto_key_exchange(dh3, spkb_prv, eka);
	displaykey("dh3", dh3, 32);

	crypto_key_exchange(dh4, opkb_prv, eka);
	displaykey("dh4", dh4, 32);

	crypto_blake2b_general(sk, 32, NULL, 0, dh, 128);
	displaykey("sk", sk, 32);

	crypto_wipe(dh, 128);

	putchar('\n');

	memcpy(ad, ika, 32);
	memcpy(ad + 32, ikb, 32);

	result = crypto_unlock_aead(text, sk, nonce, mac, ad, 64, text, msg->text_size);
	if (result != 0) {
		printf("Decryption failed!\n");
		abort();
	}

	printf("Decryption successful!\n");
	printf("Message: %s\n", text);

	crypto_wipe(spkb_prv, 32);
	crypto_wipe(opkb_prv, 32);

}

static int setclientup(const char *addr, const char *port);

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
};                                             /* them. we DO need to wipe!   */

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

static int try_decrypt_header(const struct cs_state *state, uint8_t hk[32], struct mesghdr *hdr);
static int try_skipped_message_keys(struct cs_state *state, struct mesg *mesg, size_t mesg_size);
static int mesg_try_unlock(struct cs_state *state, struct mesg *mesg, size_t mesg_size);
static int mesg_unlock(uint8_t mk[32], struct mesg *mesg, size_t mesg_size, const uint8_t *ad, size_t ad_size);
static void mesg_lock(struct cs_state *state, struct mesg *mesg, size_t mesg_size);

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

	displaykey("hk", hk, 32);
	displaykey("nonce", hdr->nonce, 24);
	displaykey("hdrmac", hdr->hdrmac, 16);

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
			crypto_wipe(bucket->hk, 32);
			bucket->next = state->spare_buckets;
			state->spare_buckets = bucket;
		detach_mesgkey:
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
	if (until >= MAX_SKIP && state->nr >= until - MAX_SKIP) {
		/* TODO: error handling */
		fprintf(stderr, "Too many messages to skip. Abort.\n");
		exit(EXIT_FAILURE);
	}

	if (!crypto_verify32(state->rek, missing_key) || state->nr >= until) {
		return;
	}

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
			mesgkey->msn = state->nr;
			cs_symm_ratchet(mesgkey->mk, state->rek);
			mesgkey->next = NULL;
			state->nr++;
		}
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

	fprintf(stderr, "trying skipped message keys\n");
	if (!try_skipped_message_keys(state, mesg, mesg_size)) {
		return 0;
	}

	fprintf(stderr, "trying to decrypt header with current hk\n");
	if (try_decrypt_header(state, state->hkr, &mesg->hdr)) {
		fprintf(stderr, "trying to decrypt header with next hk\n");
		if (try_decrypt_header(state, state->nhkr, &mesg->hdr)) {
			fprintf(stderr, "couldn't decrypt header with any hk\n");
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
	memcpy(mesg->hdr.msn, &state->ns, 4);
	memcpy(mesg->hdr.pn, &state->pn, 4);
	memcpy(mesg->hdr.pk, state->dhks, 32);

	displaykey("mk", mk, 32);

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

	displaykey("hk", state->hks, 32);
	displaykey("nonce", mesg->hdr.nonce, 24);
	displaykey("hplain", ((uint8_t *)&mesg->hdr) + offsetof(struct mesghdr, msn), sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));
	fprintf(stderr, "text_size=(%lu)\n", sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	crypto_lock_aead(
		mesg->hdr.hdrmac,
		((uint8_t *)&mesg->hdr) + offsetof(struct mesghdr, msn),
		state->hks,
		mesg->hdr.nonce,
		state->ad,
		state->ad_size,
		((uint8_t *)&mesg->hdr) + offsetof(struct mesghdr, msn),
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	displaykey("mac", mesg->hdr.hdrmac, 16);
	displaykey("hcrypt", ((uint8_t *)&mesg->hdr) + offsetof(struct mesghdr, msn), sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

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

static void safe_write(int fd, const uint8_t *buf, size_t size);
static size_t safe_read(int fd, uint8_t *buf, size_t size);

static const uint8_t cs_hs_info[]   = "AetherwindClientServerHandshake";
static const uint8_t cs_symm_info[] = "AetherwindClientServerSymmetricRatchet";
static const uint8_t cs_dh_info[]   = "AetherwindClientServerDiffieHellmanRatchet";
static const uint8_t pp_hs_info[]   = "AetherwindPeerToPeerHandshake";
static const uint8_t pp_symm_info[] = "AetherwindPeerToPeerSymmetricRatchet";
static const uint8_t pp_dh_info[]   = "AetherwindPeerToPeerDiffieHellmanRatchet";

/* RFC 5869 HKF with Hash=BLAKE2b but please note the additional (unchecked) requirements.
 * Derived_key_size MUST be a multiple of 32.
 * MOST IMPORTANTLY, derived_key must point to a buffer that
 * can contain at least derived_key_size + info_size + 1.
 * After this function it will contain the derived_key of the
 * desired size and then info_size + 1 zeroes.
 * There are reasonable size limits on the inputs too.
 * (Also please read the whole RFC.  It's not very long.)
 *
 * hkdf_blake2b wipes its own internal buffers, but not the salt or info.
 * crypto_wipe is your friend. :)
 */
static
void
hkdf_blake2b(uint8_t *derived_key,   size_t derived_key_size,
		const uint8_t *salt, size_t salt_size,
		const uint8_t *info, size_t info_size,
		const uint8_t *ikm,  size_t ikm_size)
{
	uint8_t prk[64];
	uint8_t *dkptr;

	/* HKDF-Extract */
	crypto_blake2b_general(prk, 64, salt, salt_size, ikm, ikm_size);

	/* HKDF-Expand */
	memcpy(derived_key + derived_key_size, info, info_size);
	derived_key[derived_key_size + info_size] = 0;

	for (dkptr = derived_key + derived_key_size; dkptr > derived_key; dkptr -= 32) {
		/* wrapping overflow of uint8_t is intended */
		derived_key[derived_key_size + info_size]++;
		/* message_size arg is (iterations * 32) + info_size + 1 */
		crypto_blake2b_general(dkptr - 32, 32, prk, 64, dkptr,
			derived_key_size - (dkptr - derived_key) + info_size + 1);
	}

	crypto_wipe(derived_key + derived_key_size, info_size + 1);
	crypto_wipe(prk, 64);
}

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

static
void
c_alice(const char *addr, const char *port)
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
	uint8_t buf[65536];
	uint8_t dh[128];
	uint8_t *dh1 = dh, *dh2 = dh + 32;
	uint8_t *dh3 = dh + 64, *dh4 = dh + 96;
	uint8_t hk[32], nhk[32], sk[32];
	uint8_t iks[32], eks[32];
	struct cs_state state;

	memset(&initmsg, 0, sizeof initmsg);

	generate_sig_keypair(iskc, iskc_prv);
	displaykey("iskc",     iskc, 32);
	displaykey("iskc.prv", iskc_prv, 32);

	putchar('\n');

	generate_kex_keypair(ikc, ikc_prv);
	displaykey("ikc",     ikc,     32);
	displaykey("ikc.prv", ikc_prv, 32);

	sign_key(iskc_prv, iskc, "AECI", ikc, ikc_sig);

	fd = setclientup(addr, port);

	putchar('\n');

	generate_kex_keypair(ekc, ekc_prv);
	displaykey("ekc",     ekc,     32);
	displaykey("ekc.prv", ekc_prv, 32);

	randbytes(cvc, 32);

	memcpy(initmsg.iskc,    iskc,    32);
	memcpy(initmsg.ikc,     ikc,     32);
	memcpy(initmsg.ekc,     ekc,     32);
	memcpy(initmsg.ikc_sig, ikc_sig, 64);
	memcpy(initmsg.cvc,     cvc,     32);
	sign_key(iskc_prv, iskc, "AECE", ekc, initmsg.ekc_sig);

	putchar('\n');

	safe_write(fd, (const uint8_t *)&initmsg, sizeof initmsg);
	crypto_wipe((uint8_t *)&initmsg, sizeof initmsg);

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

		/* not right
		memset(state.rok,      0,       32);
		memcpy(state.sek,      sk,      32);
		memset(state.nhks,     0,       32);
		*/

		/* the first message of the post-x3dh protocol: */

		{
#define MESG_SIZE 256
			union {
				uint8_t buf[sizeof(struct mesg) + MESG_SIZE];
				struct mesg mesg;
			} mesgbuf;
			memset(mesgbuf.mesg.text, 0x55, MESG_SIZE);
			displaykey("plain", mesgbuf.buf, sizeof(struct mesg) + MESG_SIZE);
			mesg_lock(&state, &mesgbuf.mesg, MESG_SIZE);
			displaykey("crypt", mesgbuf.buf, sizeof(struct mesg) + MESG_SIZE);
			safe_write(fd, mesgbuf.buf, sizeof(struct mesg) + MESG_SIZE);

#undef MESG_SIZE
		}
	}

fail:
	/* TODO: make sure absolutely everything is wiped here */
	exit(EXIT_FAILURE);
}

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

/*
static
void
safe_write_wrtn(int fd, const uint8_t *buf, size_t size)
{
	ssize_t result;
	size_t written = 0;

	result = write(fd, buf, size);
	while (result == -1 || written + (size_t)result < size) {
		if (result == -1 && errno == EINTR) {
			result = write(fd, buf + written, size - written);
			continue;
		}
		if (result == -1) {
			fprintf(stderr, "Error while writing to socket.\n");
			exit(EXIT_FAILURE);
		}
		written += result;
		result = write(fd, buf + written, size - written);
	}
}
*/

static
void
c_bob(const char *addr, const char *port)
{
	uint8_t buf[128];
	ssize_t nread;
	int fd;

	fd = setclientup(addr, port);

	for (;;) {
		nread = write(fd, buf, 128);
		if (nread != 128)
			continue;

		fprintf(stderr, "Received %zd bytes.\n", nread);
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
	displaykey("iks",     iks,     32);
	displaykey("iks.prv", iks_prv, 32);

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
			putchar('\n');

			generate_kex_keypair(eks, eks_prv);
			displaykey("eks",     eks,     32);
			displaykey("eks.prv", eks_prv, 32);

			randbytes(cvs, 32);
			displaykey("cvs", cvs, 32);

			/* Signing iks only ever needs to be done once */
			memcpy(servmsg.iks, iks, 32);
			memcpy(servmsg.eks, eks, 32);
			sign_key(isks_prv, isks, "AESI", iks, servmsg.iks_sig);
			sign_key(isks_prv, isks, "AESE", eks, servmsg.eks_sig);
			sign_key(isks_prv, isks, "AESC", initmsg->cvc, servmsg.cvc_sig);
			memcpy(servmsg.cvs, cvs, 32);

			putchar('\n');

			displaykey("iks_sig", servmsg.iks_sig, 64);
			displaykey("eks_sig", servmsg.eks_sig, 64);
			displaykey("cvc_sig", servmsg.cvc_sig, 64);

			safe_sendto(fd, (const uint8_t *)&servmsg, sizeof servmsg,
				(struct sockaddr *)&peeraddr, peeraddr_len);
			crypto_wipe((uint8_t *)&servmsg, sizeof servmsg);

			crypto_key_exchange(dh1, iks_prv, initmsg->ikc);
			crypto_key_exchange(dh2, iks_prv, initmsg->ekc);
			crypto_key_exchange(dh3, eks_prv, initmsg->ikc);
			crypto_key_exchange(dh4, eks_prv, initmsg->ekc);

			putchar('\n');

			compute_shared_secrets(sk, nhk, hk, dh);

			/* Is this correct ? */
			/*crypto_wipe(eks_prv, 32);*/
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
			displaykey("plain", (const uint8_t *)buf, sizeof(struct mesg) + MESG_SIZE);
			if (mesg_try_unlock(&state, mesg, MESG_SIZE)) {
				fprintf(stderr, "Couldn't decrypt\n");
			} else {
				fprintf(stderr, "Could decrypt\n");
			}
#undef MESG_SIZE
		}
	}
}

/* 128-byte DH=[dh1|dh2|dh3|dh4]
 * [dh1|dh2] hashed to sd1=[sd1A|sd1B]
 * [dh3|dh4] hashed to sd2=[sd2A|sd2B]
 * [sd1A|sd2A] hashed to [nhk|hk]
 * [sd1B|sd2B] hashed to [sk0]
 *
static
void
compute_shared_secrets(uint8_t *sk, uint8_t *nhk, uint8_t *hk, uint8_t *dh)
{
	uint8_t sd1[64], sd2[64], tmp[32];

	 * [dh1|dh2] hashed to sd1=[sd1A|sd1B]
	 * [dh3|dh4] hashed to sd2=[sd2A|sd2B]
	 * 
	crypto_blake2b(sd1, dh,      64);
	crypto_blake2b(sd2, dh + 64, 64);

	 * sd1=[sd1A|sd1B] swapped to [sd1A|sd2A]
	 * sd2=[sd2A|sd2B] swapped to [sd1B|sd2B]
	 * 
	memcpy(tmp,      sd2,      32);
	memcpy(sd2,      sd1 + 32, 32);
	memcpy(sd1 + 32, tmp,      32);

	crypto_wipe(tmp, 32);

	 *
	 * [sd1A|sd2A] hashed to [nhk|hk]
	 * [sd1B|sd2B] hashed to [sk]
	 * 
	crypto_blake2b(sd1, sd1, 64);
	crypto_blake2b_general(sk, 32, NULL, 0, sd2, 64);

	memcpy(nhk, sd1, 32);
	memcpy(hk,  sd1 + 32, 32);

	displaykey("hk",  hk,  32);
	displaykey("nhk", nhk, 32);
	displaykey("sk", sk, 32);

	crypto_wipe(dh, 128);
	crypto_wipe(sd1, 64);
	crypto_wipe(sd2, 64);
}
*/

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
	/*
	uint8_t ika[32], eka[32], iskb[32], ikb[32], spkb[32], opkb[32];
	uint8_t ika_prv[32], eka_prv[32];
	uint8_t iskb_prv[32], ikb_prv[32], spkb_prv[32], opkb_prv[32];
	uint8_t ikb_sig[64], spkb_sig[64], opkb_sig[64];
	*/
	const char *host, *port;
	/*
	struct init_msg *msg;
	*/

	if (argc != 4) 
		usage(argv[0]);

	host = argv[1];
	port = argv[2];

	/*
	bob_generate_keys(iskb, ikb, spkb, opkb,
		iskb_prv, ikb_prv, spkb_prv, opkb_prv);
	putchar('\n');
	bob_sign_keys(iskb, iskb_prv, ikb, spkb, opkb,
		ikb_sig, spkb_sig, opkb_sig);
	putchar('\n');
	alice_generate_keys(ika, eka, ika_prv, eka_prv);
	putchar('\n');
	alice(&msg, ika, ika_prv, eka, eka_prv,
		iskb, ikb, ikb_sig, spkb, spkb_sig, opkb, opkb_sig);
	if (msg == NULL)
		abort();
	putchar('\n');
	bob(msg, ikb, ikb_prv, spkb_prv, opkb_prv);

	(void)mboxes;
	*/

	switch (argv[3][0]) {
		case 's': serve(host, port); break;
		case 'a': c_alice(host, port); break;
		case 'b': c_bob(host, port); break;
		default:  usage(argv[0]);
	}

	return 0;
}
