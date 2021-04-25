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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "util.h"
#include "mesg.h"
#include "hkdf.h"
#include "monocypher.h"

#define MAX_SKIP 1000
#define AD_SIZE  64

/* TODO: discover through DNS or HTTPS or something */
#include "isks.h"

static void symm_ratchet(uint8_t mk[32], uint8_t ckn[32]);
static void dh_ratchet(uint8_t rk[32], uint8_t ckn[32], uint8_t nhk[32], uint8_t dh[32]);

static int try_decrypt_header(const struct mesg_ratchet_state *state, uint8_t hk[32], struct mesghdr *hdr);
static int try_skipped_message_keys(struct mesg_ratchet_state *state, struct mesg *mesg, size_t mesg_size);
static int skip_message_keys(struct mesg_ratchet_state *state, uint32_t until);
static int skip_message_keys_helper(struct mesg_ratchet_state *state, uint32_t until);
static int decrypt_message(uint8_t mk[32], struct mesg *mesg, size_t mesg_size, const uint8_t *ad);
static int try_decrypt_message(struct mesg_ratchet_state *state, struct mesg *mesg, size_t mesg_size);
static void encrypt_message(struct mesg_ratchet_state *state, struct mesg *mesg, size_t mesg_size);

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

static const uint8_t hs_info[]   = "AetherwindHandshake";
static const uint8_t rep_info[]  = "AetherwindReplyHandshake";
static const uint8_t symm_info[] = "AetherwindSymmetricRatchet";
static const uint8_t dh_info[]   = "AetherwindDiffieHellmanRatchet";

static const uint8_t zero_nonce[24];
static const uint8_t missing_key[32];

static struct mesgkey_bucket *spare_buckets = NULL;
static struct mesgkey *spare_mesgkeys = NULL;

struct mesgkey {
	uint32_t msn;
	uint8_t mk[32];
	struct mesgkey *next;
};

struct mesgkey_bucket {
	uint8_t hk[32];
	struct mesgkey *first;
	struct mesgkey_bucket *next;
};

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
try_decrypt_header(const struct mesg_ratchet_state *state,
		uint8_t hk[32], struct mesghdr *hdr)
{
	return crypto_unlock_aead(
		hdr->msn,
		hk,
		hdr->nonce,
		hdr->hdrmac,
		state->ad,
		AD_SIZE,
		hdr->msn,
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));
}

static
int
try_skipped_message_keys(struct mesg_ratchet_state *state, struct mesg *mesg, size_t mesg_size)
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
			if (decrypt_message(mesgkey->mk, mesg, mesg_size, state->ad))
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
bucket_create(struct mesg_ratchet_state *state)
{
	struct mesgkey_bucket *b;

	if (NULL != (b = state->spare_buckets)) {
		state->spare_buckets = b->next;
		return b;
	}

	if (NULL != (b = spare_buckets)) {
		spare_buckets = b->next;
		return b;
	}

	return malloc(sizeof *b);
}

static
struct mesgkey *
mesgkey_create(struct mesg_ratchet_state *state)
{
	struct mesgkey *m;

	if (NULL != (m = state->spare_mesgkeys)) {
		state->spare_mesgkeys = m->next;
		return m;
	}

	if (NULL != (m = spare_mesgkeys)) {
		spare_mesgkeys = m->next;
		return m;
	}

	return malloc(sizeof *m);
}

static
int
skip_message_keys(struct mesg_ratchet_state *state, uint32_t until)
{
	if (MAX_SKIP == 0)
		return -1;

	if (until >= (MAX_SKIP + 1) && state->nr >= until - (MAX_SKIP + 1))
		return -1;

	if (!crypto_verify32(state->ckr, missing_key) || state->nr >= until)
		return 0;

	return skip_message_keys_helper(state, until);
}

static
int
skip_message_keys_helper(struct mesg_ratchet_state *state, uint32_t until)
{
	struct mesgkey *prev_mesgkey = NULL;
	struct mesgkey_bucket *bucket;

	bucket = bucket_create(state);
	if (bucket == NULL)
		return -1;

	memcpy(bucket->hk, state->hkr, 32);
	bucket->next = state->skipped;
	state->skipped = bucket;

	while (state->nr < until) {
		struct mesgkey *mesgkey = mesgkey_create(state);

		if (mesgkey == NULL)
			return -1;

		if (prev_mesgkey == NULL)
			bucket->first = mesgkey;
		else
			prev_mesgkey->next = mesgkey;
		prev_mesgkey = mesgkey;

		mesgkey->msn = state->nr;
		symm_ratchet(mesgkey->mk, state->ckr);
		mesgkey->next = NULL;

		state->nr++;
	}

	return 0;
}

static
void
step_receiver_ratchet(struct mesg_ratchet_state *state, struct mesghdr *hdr)
{
	uint8_t dh[32];

	state->pn = state->ns;
	state->ns = 0;
	state->nr = 0;

	memcpy(state->hks, state->nhks, 32);
	memcpy(state->hkr, state->nhkr, 32);

	memcpy(state->dhkr, hdr->pk, 32);

	crypto_key_exchange(dh, state->dhks_prv, state->dhkr);
	dh_ratchet(state->rk, state->ckr, state->nhkr, dh);

	generate_kex_keypair(state->dhks, state->dhks_prv);
	crypto_key_exchange(dh, state->dhks_prv, state->dhkr);
	dh_ratchet(state->rk, state->cks, state->nhks, dh);

	crypto_wipe(dh, 32);
}

static
int
try_decrypt_message(struct mesg_ratchet_state *state, struct mesg *mesg, size_t mesg_size)
{
	uint8_t mk[32];
	int result;

	if (!try_skipped_message_keys(state, mesg, mesg_size))
		return 0;

	if (try_decrypt_header(state, state->hkr, &mesg->hdr)) {
		if (try_decrypt_header(state, state->nhkr, &mesg->hdr))
			return -1;
		if (skip_message_keys(state, load32_le(mesg->hdr.pn)))
			return -1;
		step_receiver_ratchet(state, &mesg->hdr);
	}
	if (skip_message_keys(state, load32_le(mesg->hdr.msn)))
		return -1;

	symm_ratchet(mk, state->ckr);
	state->nr++;

	result = decrypt_message(mk, mesg, mesg_size, state->ad);
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
decrypt_message(uint8_t mk[32], struct mesg *mesg, size_t mesg_size,
		const uint8_t *ad)
{
	int result;

	result = crypto_unlock_aead(
		mesg->text,
		mk,
		zero_nonce,
		mesg->hdr.mac,
		ad,
		AD_SIZE,
		mesg->text,
		mesg_size);

	if (result == 0) {
		crypto_wipe(mk, 32);
	}

	return result;
}

void
mesg_lock(struct mesg_state *state, uint8_t *buf, size_t text_size)
{
	encrypt_message(&state->u.ra, (struct mesg *)buf, text_size);
}

int
mesg_unlock(struct mesg_state *state, uint8_t *buf, size_t buf_size)
{
	return try_decrypt_message(&state->u.ra,
		(struct mesg *)buf, buf_size - sizeof(struct mesg));
}

static
void
encrypt_message(struct mesg_ratchet_state *state, struct mesg *mesg, size_t mesg_size)
{
	uint8_t mk[32];

	symm_ratchet(mk, state->cks);

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
		AD_SIZE,
		mesg->text,
		mesg_size);

	randbytes(mesg->hdr.nonce, 24);

	crypto_lock_aead(
		mesg->hdr.hdrmac,
		mesg->hdr.msn,
		state->hks,
		mesg->hdr.nonce,
		state->ad,
		AD_SIZE,
		mesg->hdr.msn,
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	crypto_wipe(mk, 32);

	state->ns++;
}

static
void
symm_ratchet(uint8_t mk[32], uint8_t ckn[32])
{
	uint8_t tmp[64 + sizeof(symm_info) + 1];

	hkdf_blake2b(
		tmp,       64,
		NULL,      0,
		symm_info, sizeof(symm_info),
		ckn,       32);

	memcpy(mk,  tmp,      32);
	memcpy(ckn, tmp + 32, 32);

	crypto_wipe(tmp, 64);
}

static
void
dh_ratchet(uint8_t rk[32], uint8_t ck[32], uint8_t nhk[32], uint8_t dh[32])
{
	uint8_t tmp[96 + sizeof(dh_info) + 1];

	hkdf_blake2b(
		tmp,     96,
		rk,      32,
		dh_info, sizeof(dh_info),
		dh,      32);

	memcpy(rk,  tmp,      32);
	memcpy(ck,  tmp + 32, 32);
	memcpy(nhk, tmp + 64, 32);

	crypto_wipe(dh, 32);
	crypto_wipe(tmp, 96);
}

static
void
hshake_compute_shared_secrets(uint8_t sk[32], uint8_t nhk[32], uint8_t hk[32],
		uint8_t dh[128])
{
	uint8_t tmp[96 + sizeof(hs_info) + 1];

	hkdf_blake2b(
		tmp,     96,
		NULL,    0,
		hs_info, sizeof(hs_info),
		dh,      128);

	memcpy(sk,  tmp,      32);
	memcpy(hk,  tmp + 32, 32);
	memcpy(nhk, tmp + 64, 32);

	crypto_wipe(dh, 128);
	crypto_wipe(tmp, 96);
}

void
mesg_hshake_dprepare(struct mesg_state *state,
		const uint8_t iskd[32], const uint8_t iskd_prv[32],
		const uint8_t ikd[32], const uint8_t ikd_prv[32])
{
	struct mesg_hshake_dstate *hsd = &state->u.hsd;

	crypto_wipe(state, sizeof *state);

	memcpy(hsd->iskd,    iskd,     32);
	memcpy(hsd->iskd_prv,iskd_prv, 32);
	memcpy(hsd->ikd,     ikd,      32);
	memcpy(hsd->ikd_prv, ikd_prv,  32);
	generate_kex_keypair(hsd->ekd, hsd->ekd_prv);
	randbytes(hsd->cvd, 32);
}

void
mesg_hshake_cprepare(struct mesg_state *state,
		const uint8_t iskd[32], const uint8_t ikd[32],
		const uint8_t iskc[32], const uint8_t iskc_prv[32],
		const uint8_t ikc[32], const uint8_t ikc_prv[32])
{
	struct mesg_hshake_cstate *hsc = &state->u.hsc;

	crypto_wipe(state, sizeof *state);

	memcpy(hsc->iskd,    iskd,     32);
	memcpy(hsc->ikd,     ikd,      32);
	memcpy(hsc->iskc,    iskc,     32);
	memcpy(hsc->iskc_prv,iskc_prv, 32);
	memcpy(hsc->ikc,     ikc,      32);
	memcpy(hsc->ikc_prv, ikc_prv,  32);
	generate_kex_keypair(hsc->ekc, hsc->ekc_prv);
	generate_hidden_keypair(hsc->hkc, hsc->hkc_prv);
	randbytes(hsc->cvc, 32);
}

static
void
hello_compute_shared_secrets(uint8_t hk[32], uint8_t rk[32],
		const uint8_t prv[32], const uint8_t pub[32])
{
	uint8_t raw_shared[32];
	uint8_t shared[64 + sizeof(rep_info) + 1];

	crypto_x25519(raw_shared, prv, pub);
	hkdf_blake2b(shared, 64, NULL, 0, rep_info, sizeof rep_info, raw_shared, 32);
	crypto_wipe(raw_shared, 32);

	memcpy(hk, shared,      32);
	memcpy(rk, shared + 32, 32);
	crypto_wipe(shared, 64);
}

void
mesg_hshake_chello(struct mesg_state *state, uint8_t buf[MESG_HELLO_SIZE])
{
	struct mesg_hshake_cstate *hsc = &state->u.hsc;
	struct hshake_hello_msg *hellomsg = (struct hshake_hello_msg *)buf;
	uint8_t hellokey[32];

	/* content of the hello message */
	memcpy(hellomsg->iskc,   hsc->iskc, 32);
	memcpy(hellomsg->ikc,    hsc->ikc,  32);
	memcpy(hellomsg->ekc,    hsc->ekc,  32);
	memcpy(hellomsg->cvc,    hsc->cvc,  32);
	sign_key(hellomsg->ikc_sig, hsc->iskc_prv, hsc->iskc, "AHCI", hsc->ikc);
	sign_key(hellomsg->ekc_sig, hsc->iskc_prv, hsc->iskc, "AHCE", hsc->ekc);

	/* encrypt the hello message */
	memcpy(hellomsg->hidden, hsc->hkc,  32);
	hello_compute_shared_secrets(hellokey, hsc->shared, hsc->hkc_prv, hsc->ikd);

	crypto_lock(hellomsg->mac,
		hellomsg->iskc,
		hellokey,
		zero_nonce,
		hellomsg->iskc,
		sizeof(struct hshake_hello_msg) - offsetof(struct hshake_hello_msg, iskc));
	crypto_wipe(hellokey, 32);
}

static
int
try_decrypt_hello(struct mesg_hshake_dstate *hsd, struct hshake_hello_msg *hellomsg)
{
	uint8_t hellokey[32];
	int result;

	crypto_hidden_to_curve(hellomsg->hidden, hellomsg->hidden);
	hello_compute_shared_secrets(hellokey, hsd->shared, hsd->ikd_prv, hellomsg->hidden);
	result = crypto_unlock(
		hellomsg->iskc,
		hellokey,
		zero_nonce,
		hellomsg->mac,
		hellomsg->iskc,
		MESG_HELLO_SIZE - offsetof(struct hshake_hello_msg, iskc));

	crypto_wipe(hellokey, 32);

	return result;
}

int
mesg_hshake_dcheck(struct mesg_state *state, uint8_t buf[MESG_HELLO_SIZE])
{
	struct mesg_hshake_dstate *hsd = &state->u.hsd;
	struct hshake_hello_msg *hellomsg = (struct hshake_hello_msg *)buf;

	if (try_decrypt_hello(hsd, hellomsg))
		return -1;
	if (check_key(hellomsg->iskc, "AHCI", hellomsg->ikc, hellomsg->ikc_sig))
		return -1;
	if (check_key(hellomsg->iskc, "AHCE", hellomsg->ekc, hellomsg->ekc_sig))
		return -1;

	memcpy(hsd->cvc, hellomsg->cvc, 32);
	memcpy(hsd->ikc, hellomsg->ikc, 32);
	memcpy(hsd->ekc, hellomsg->ekc, 32);

	return 0;
}

void
mesg_hshake_dreply(struct mesg_state *state, uint8_t buf[MESG_REPLY_SIZE])
{
	struct mesg_hshake_dstate *hsd = &state->u.hsd;
	struct mesg_ratchet_state *ra = &state->u.ra;
	struct hshake_reply_msg *replymsg = (struct hshake_reply_msg *)buf;
	uint8_t dh[128];
	uint8_t ikc[32], ikd[32], ekd_prv[32];

	memcpy(replymsg->eks, hsd->ekd, 32);
	sign_key(replymsg->eks_sig, hsd->iskd_prv, hsd->iskd, "AHDE", hsd->ekd);
	sign_key(replymsg->cvc_sig, hsd->iskd_prv, hsd->iskd, "AHDC", hsd->cvc);
	memcpy(replymsg->cvs, hsd->cvd, 32);

	crypto_lock(
		replymsg->mac,
		replymsg->eks,
		hsd->shared,
		zero_nonce,
		replymsg->eks,
		MESG_REPLY_SIZE - offsetof(struct hshake_reply_msg, eks));

	crypto_key_exchange(dh,      hsd->ikd_prv, hsd->ikc);
	crypto_key_exchange(dh + 32, hsd->ikd_prv, hsd->ekc);
	crypto_key_exchange(dh + 64, hsd->ekd_prv, hsd->ikc);
	crypto_key_exchange(dh + 96, hsd->ekd_prv, hsd->ekc);

	memcpy(ikc,     hsd->ikc,     32);
	memcpy(ikd,     hsd->ikd,     32);
	memcpy(ekd_prv, hsd->ekd_prv, 32);

	/* switch from hshake state to ratchet state */
	crypto_wipe(state, sizeof *state);

	hshake_compute_shared_secrets(ra->rk, ra->nhks, ra->nhkr, dh);
	memcpy(ra->dhks,     replymsg->eks, 32);
	memcpy(ra->dhks_prv, ekd_prv,       32);
	memcpy(ra->ad,       ikc,           32);
	memcpy(ra->ad + 32,  ikd,           32);
	memcpy(ra->cv,       replymsg->cvs, 32);

	crypto_wipe(ikc,     32);
	crypto_wipe(ekd_prv, 32);
	crypto_wipe(dh,     128);
}

static
int
try_decrypt_reply(struct mesg_hshake_cstate *hsc, struct hshake_reply_msg *replymsg)
{
	int result;

	result = crypto_unlock(
		replymsg->eks,
		hsc->shared,
		zero_nonce,
		replymsg->mac,
		replymsg->eks,
		MESG_REPLY_SIZE - offsetof(struct hshake_reply_msg, eks));

	if (!result)
		crypto_wipe(hsc->shared, 32);

	return result;
}

int
mesg_hshake_cfinish(struct mesg_state *state, uint8_t buf[MESG_REPLY_SIZE])
{
	struct mesg_hshake_cstate *hsc = &state->u.hsc;
	struct mesg_ratchet_state *ra = &state->u.ra;
	struct hshake_reply_msg *replymsg = (struct hshake_reply_msg *)buf;
	uint8_t dh_hs[128];
	uint8_t dh_ra[32];
	uint8_t ikc[32], ikd[32];
	int result = -1;

	if (try_decrypt_reply(hsc, replymsg))
		goto end;

	if (check_key(hsc->iskd, "AHDE", replymsg->eks, replymsg->eks_sig))
		goto end;
	if (check_key(hsc->iskd, "AHDC", hsc->cvc,      replymsg->cvc_sig))
		goto end;

	crypto_key_exchange(dh_hs,      hsc->ikc_prv, hsc->ikd);
	crypto_key_exchange(dh_hs + 32, hsc->ekc_prv, hsc->ikd);
	crypto_key_exchange(dh_hs + 64, hsc->ikc_prv, replymsg->eks);
	crypto_key_exchange(dh_hs + 96, hsc->ekc_prv, replymsg->eks);

	memcpy(ikc, hsc->ikc, 32);
	memcpy(ikd, hsc->ikd, 32);

	/* switch from hshake state to ratchet state */
	crypto_wipe(state, sizeof(struct mesg_state));

	hshake_compute_shared_secrets(ra->rk, ra->nhkr, ra->hks, dh_hs);
	generate_kex_keypair(ra->dhks, ra->dhks_prv);
	memcpy(ra->ad,      ikc,           32);
	memcpy(ra->ad + 32, ikd,           32);
	memcpy(ra->cv,      replymsg->cvs, 32);

	crypto_key_exchange(dh_ra, ra->dhks_prv, replymsg->eks);
	dh_ratchet(ra->rk, ra->cks, ra->nhks, dh_ra);
	result = 0;

end:	crypto_wipe(ikc,    32);
	crypto_wipe(dh_ra,  32);
	crypto_wipe(dh_hs, 128);

	return result;
}

#define MAX_SIZE 4096

int
mesg_example1(int fd)
{
	/* These need to be obtained somehow */
	uint8_t server_sign_public_key[32];
	uint8_t server_kex_public_key[32];
	/* In reality these are long-term keys, not generated every time. */
	uint8_t sign_public_key[32], sign_private_key[32];
	uint8_t kex_public_key[32], kex_private_key[32];
	struct mesg_state state;

	memcpy(server_sign_public_key, isks, 32);
	(void)isks_prv;
	memcpy(server_sign_public_key, iks, 32);
	(void)iks_prv;

	generate_sign_keypair(sign_public_key, sign_private_key);
	generate_kex_keypair(kex_public_key, kex_private_key);

	{
		uint8_t buf[MESG_HSHAKE_SIZE];

		/* Prepare the message state for the first handshake message */
		mesg_hshake_cprepare(&state,
			server_sign_public_key, server_kex_public_key,
			sign_public_key, sign_private_key,
			kex_public_key, kex_private_key);

		/* Create the HELLO message and update state */
		mesg_hshake_chello(&state, buf);

		/* Write the hello message out to a socket */
		write(fd, buf, MESG_HELLO_SIZE);

		/* Wipe the hello message now it has been sent */
		crypto_wipe(buf, MESG_HELLO_SIZE);

		/* Read a reply back from the peer */
		read(fd, buf, MESG_REPLY_SIZE);

		/* Check the handshake reply's integrity and update state */
		if (mesg_hshake_cfinish(&state, buf))
			return -1;
		
		/* Wipe the reply message now it has been checked */
		crypto_wipe(buf, MESG_REPLY_SIZE);
	}

	return 0;
}

int
mesg_example2(int fd)
{
	/* In reality these are long-term keys, not generated every time. */
	uint8_t sign_public_key[32], sign_private_key[32];
	uint8_t kex_public_key[32], kex_private_key[32];
	struct mesg_state state;

	generate_sign_keypair(sign_public_key, sign_private_key);
	generate_kex_keypair(kex_public_key, kex_private_key);

	/* Prepare the message state as an online handshake replier */
	mesg_hshake_dprepare(&state,
		sign_public_key, sign_private_key,
		kex_public_key, kex_private_key);

	{
		uint8_t buf[MESG_HSHAKE_SIZE];

		/* Read a hello message from a peer */
		read(fd, buf, MESG_HELLO_SIZE);

		/* Check the handshake hello and update state */
		if (mesg_hshake_dcheck(&state, buf))
			return -1;

		/* Wipe the hello message now it has been checked */
		crypto_wipe(buf, MESG_HELLO_SIZE);

		/* Create the reply message and update state */
		mesg_hshake_dreply(&state, buf);

		/* Write the reply message out to the socket */
		write(fd, buf, MESG_REPLY_SIZE);

		/* Wipe the reply message now it has been sent */
		crypto_wipe(buf, MESG_REPLY_SIZE);
	}

	return 0;
}
