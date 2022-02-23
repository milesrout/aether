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
#include "msg.h"
#include "ident.h"
#include "messaging.h"
#include "mesg.h"
#include "hkdf.h"
#include "monocypher.h"

#define MAX_SKIP 1000
#define AD_SIZE  64
#define AAD_SIZE 104

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
static const uint8_t ohs_info[]  = "AetherwindOfflineHandshake";
static const uint8_t rep_info[]  = "AetherwindReplyHandshake";
static const uint8_t symm_info[] = "AetherwindSymmetricRatchet";
static const uint8_t dh_info[]   = "AetherwindDiffieHellmanRatchet";

static const uint8_t zero_nonce[24];
static const uint8_t zero_key[32];

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

size_t
padme_enc(size_t l)
{
	return MESG_TEXT_SIZE(padme(MESG_BUF_SIZE(l)));
}

static void offline_shared_secrets(uint8_t sk[32], uint8_t nhk[32], uint8_t hk[32], uint8_t *dh, size_t dh_size);

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

/* attempt to decrypt the header of an encrypted message
 * mesg should be a struct mesg that has NOT had its header decrypted
 * hdrmac: valid
 * nonce:  valid
 * mac:    HENCRYPT'd
 * msn:    HENCRYPT'd
 * pn:     HENCRYPT'd
 * pk:     HENCRYPT'd
 * text:   ENCRYPT'd
 *
 * if the header was decrypted successfully, returns 0
 *       -> WITHOUT WIPING THE HEADER KEY. <-
 * otherwise returns -1;
 */
static
int
try_decrypt_header(const struct mesg_ratchet_state_common *ra,
		uint8_t hk[32], struct mesghdr *hdr)
{
	int result;

	result = crypto_unlock_aead(
		hdr->msn,
		hk,
		hdr->nonce,
		hdr->hdrmac,
		ra->ad,
		AD_SIZE,
		hdr->msn,
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	/* if (!result) { */
	/* 	crypto_wipe(hdr->hdrmac, 16); */
	/* 	crypto_wipe(hdr->nonce,  24); */
	/* } */

	return result;
}

/* decrypt a partially decrypted message
 * mesg should be a struct mesg that has had its header decrypted
 * hdrmac: should have been wiped already
 * nonce:  should have been wiped already
 * mac:    valid
 * msn:    valid
 * pn:     valid
 * pk:     valid
 * text:   ENCRYPT'd
 *
 * if the message was decrypted successfully, wipes mk and returns 0.
 * otherwise returns -1;
 */
static
int
decrypt_message(uint8_t mk[32], struct mesg *mesg, size_t mesg_size,
		const uint8_t *aad, size_t aad_size)
{
	int result;

	result = crypto_unlock_aead(
		mesg->text,
		mk,
		zero_nonce,
		mesg->hdr.mac,
		aad,
		aad_size,
		mesg->text,
		mesg_size);

	if (!result) {
		crypto_wipe(mk, 32);
	}

	return result;
}

#if 0
static
size_t
bucket_length(struct mesgkey_bucket *bucket)
{
	size_t n = 0;
	struct mesgkey *mesgkey = bucket->first;
	while (mesgkey) {
		n++;
		mesgkey = mesgkey->next;
	}
	return n;
}
#endif

static
int
try_skipped_message_keys(struct mesg_ratchet_state_common *ra,
	struct mesg *mesg, size_t mesg_size,
	const uint8_t *aad, size_t aad_size)
{
	struct mesgkey_bucket *prev_bucket, *bucket;
	struct mesgkey *prev_mesgkey, *mesgkey;

	prev_bucket = NULL;
	bucket = ra->skipped;

	while (bucket != NULL) {

		if (try_decrypt_header(ra, bucket->hk, &mesg->hdr)) {
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
			if (decrypt_message(mesgkey->mk, mesg, mesg_size, aad, aad_size))
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
				ra->skipped = bucket->next;
				goto detach_bucket;
			}

		detach_bucket:
			crypto_wipe(bucket, sizeof(struct mesgkey_bucket));
			bucket->next = ra->spare_buckets;
			ra->spare_buckets = bucket;
		detach_mesgkey:
			crypto_wipe(mesgkey, sizeof(struct mesgkey));
			mesgkey->next = ra->spare_mesgkeys;
			ra->spare_mesgkeys = mesgkey;
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
bucket_create(struct mesg_ratchet_state_common *ra)
{
	struct mesgkey_bucket *b;

	if (NULL != (b = ra->spare_buckets)) {
		ra->spare_buckets = b->next;
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
mesgkey_create(struct mesg_ratchet_state_common *ra)
{
	struct mesgkey *m;

	if (NULL != (m = ra->spare_mesgkeys)) {
		ra->spare_mesgkeys = m->next;
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
skip_message_keys_helper(struct mesg_ratchet_state_common *ra, uint32_t until)
{
	struct mesgkey *prev_mesgkey = NULL;
	struct mesgkey_bucket *bucket;

	bucket = bucket_create(ra);
	if (bucket == NULL)
		return -1;

	memcpy(bucket->hk, ra->hkr, 32);
	bucket->next = ra->skipped;
	ra->skipped = bucket;

	while (ra->nr < until) {
		struct mesgkey *mesgkey = mesgkey_create(ra);

		if (mesgkey == NULL)
			return -1;

		if (prev_mesgkey == NULL)
			bucket->first = mesgkey;
		else
			prev_mesgkey->next = mesgkey;
		prev_mesgkey = mesgkey;

		mesgkey->msn = ra->nr;
		symm_ratchet(mesgkey->mk, ra->ckr);
		mesgkey->next = NULL;

		ra->nr++;
	}

	return 0;
}

static
int
skip_message_keys(struct mesg_ratchet_state_common *ra, uint32_t until)
{
	if (MAX_SKIP == 0)
		return -1;

	if (until >= (MAX_SKIP + 1) && ra->nr >= until - (MAX_SKIP + 1))
		return -1;

	if (!crypto_verify32(ra->ckr, zero_key) || ra->nr >= until)
		return 0;

	return skip_message_keys_helper(ra, until);
}

static
void
step_receiver_ratchet(struct mesg_ratchet_state_common *ra, struct mesghdr *hdr)
{
	uint8_t dh[32];

	ra->pn = ra->ns;
	ra->ns = 0;
	ra->nr = 0;

	memcpy(ra->hks, ra->nhks, 32);
	memcpy(ra->hkr, ra->nhkr, 32);

	memcpy(ra->dhkr, hdr->pk, 32);

	crypto_x25519(dh, ra->dhks_prv, ra->dhkr);
	dh_ratchet(ra->rk, ra->ckr, ra->nhkr, dh);

	generate_kex_keypair(ra->dhks, ra->dhks_prv);
	crypto_x25519(dh, ra->dhks_prv, ra->dhkr);
	dh_ratchet(ra->rk, ra->cks, ra->nhks, dh);

	crypto_wipe(dh, 32);
}

static
int
try_decrypt_message(struct mesg_ratchet_state_common *ra, struct mesg *mesg, size_t mesg_size)
{
	uint8_t mk[32];
	uint8_t aad[AAD_SIZE];
	int result = -1;

	/* AAD = (AD||ENC_HEADER) */
	memcpy(aad,           ra->ad,        AD_SIZE);
	memcpy(aad + AD_SIZE, mesg->hdr.msn, AAD_SIZE - AD_SIZE);

	if (!try_skipped_message_keys(ra, mesg, mesg_size, aad, AAD_SIZE)) {
		crypto_wipe(aad, AAD_SIZE);
		return 0;
	}

	if (try_decrypt_header(ra, ra->hkr, &mesg->hdr)) {
		if (try_decrypt_header(ra, ra->nhkr, &mesg->hdr))
			goto fail;
		if (skip_message_keys(ra, load32_le(mesg->hdr.pn)))
			goto fail;
		step_receiver_ratchet(ra, &mesg->hdr);
	}
	if (skip_message_keys(ra, load32_le(mesg->hdr.msn)))
		goto fail;

	symm_ratchet(mk, ra->ckr);
	ra->nr++;

	result = decrypt_message(mk, mesg, mesg_size, aad, AAD_SIZE);
	if (!result)
		ra->prerecv = 0;
fail:
	crypto_wipe(mk, 32);
	crypto_wipe(aad, AAD_SIZE);
	return result;
}

static
void
encrypt_message(struct mesg_ratchet_state_common *ra, struct mesg *mesg, size_t mesg_size)
{
	uint8_t mk[32];
	uint8_t aad[AAD_SIZE];

	symm_ratchet(mk, ra->cks);

	store32_le(mesg->hdr.msn, ra->ns);
	store32_le(mesg->hdr.pn, ra->pn);
	memcpy(mesg->hdr.pk, ra->dhks, 32);

	randbytes(mesg->hdr.nonce, 24);

	crypto_lock_aead(
		mesg->hdr.hdrmac,
		mesg->hdr.msn,
		ra->hks,
		mesg->hdr.nonce,
		ra->ad,
		AD_SIZE,
		mesg->hdr.msn,
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	memcpy(aad,           ra->ad,        AD_SIZE);
	memcpy(aad + AD_SIZE, mesg->hdr.msn, AAD_SIZE - AD_SIZE);

	crypto_lock_aead(
		mesg->hdr.mac,
		mesg->text,
		mk,
		zero_nonce, /* (each message is sent using a one-use secret key,
		                so AEAD can use a constant nonce)
			       (perhaps this should be some other constant to
				provide domain separation?)*/
		aad,
		AAD_SIZE,
		mesg->text,
		mesg_size);

	crypto_wipe(mk, 32);
	crypto_wipe(aad, AAD_SIZE);

	ra->ns++;
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
mesg_lock(struct mesg_state *state, uint8_t *buf, size_t text_size)
{
	/* fprintf(stderr, "\nEncrypting message with size %lu (%lu)\n", */
	/* 	text_size, MESG_BUF_SIZE(text_size)); */
	encrypt_message(&state->u.ra.rac, (struct mesg *)buf, text_size);
}

int
mesg_unlock(struct mesg_state *state, uint8_t *buf, size_t buf_size)
{
	/* fprintf(stderr, "\nTrying to decrypt message with size %lu (%lu)\n", */
	/* 	MESG_TEXT_SIZE(buf_size), buf_size); */
	return try_decrypt_message(&state->u.ra.rac,
		(struct mesg *)buf, buf_size - sizeof(struct mesg));
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

	memcpy(hellomsg->iskc,   hsc->iskc, 32);
	memcpy(hellomsg->ekc,    hsc->ekc,  32);
	memcpy(hellomsg->cvc,    hsc->cvc,  32);
	memcpy(hellomsg->hidden, hsc->hkc,  32);

	hello_compute_shared_secrets(hellokey, hsc->shared, hsc->hkc_prv, hsc->ikd);

	/* just to be safe (the whole state is wiped later anyway) */
	crypto_wipe(hsc->hkc_prv, 32);

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

void
mesg_hshake_bprepare(struct mesg_state *state,
	const uint8_t ika[32], const uint8_t eka[32],
	const uint8_t ikb[32],  const uint8_t ikb_prv[32],
	const uint8_t spkb[32], const uint8_t spkb_prv[32],
	const uint8_t opkb[32], const uint8_t opkb_prv[32])
{
	struct mesg_ratchet_state_common *ra = &state->u.ra.rac;
	uint8_t dh[128];

	crypto_wipe(state, sizeof *state);

	displaykey("spkb.prv", spkb_prv, 32);
	displaykey("ikb.prv",  ikb_prv,  32);
	displaykey("opkb.prv", opkb_prv, 32);
	displaykey("ika",      ika,      32);
	displaykey("eka",      eka,      32);

	crypto_x25519(dh,      spkb_prv, ika);
	crypto_x25519(dh + 32, ikb_prv,  eka);
	crypto_x25519(dh + 64, spkb_prv, eka);

	if (!crypto_verify32(opkb, zero_key)) {
		offline_shared_secrets(ra->rk, ra->nhks, ra->nhkr, dh, 96);
	} else {
		crypto_x25519(dh + 96, opkb_prv, eka);
		offline_shared_secrets(ra->rk, ra->nhks, ra->nhkr, dh, 128);
	}

	memcpy(ra->dhks,     spkb,     32);
	memcpy(ra->dhks_prv, spkb_prv, 32);
	memcpy(ra->ad,       ika,      32);
	memcpy(ra->ad + 32,  ikb,      32);
}

int
mesg_hshake_bfinish(struct mesg_state *state, uint8_t *buf, size_t size)
{
	return mesg_unlock(state, buf, size);
}

int
mesg_hshake_dcheck(struct mesg_state *state, uint8_t buf[MESG_HELLO_SIZE])
{
	struct mesg_hshake_dstate *hsd = &state->u.hsd;
	struct hshake_hello_msg *hellomsg = (struct hshake_hello_msg *)buf;

	if (try_decrypt_hello(hsd, hellomsg))
		return -1;

	memcpy(hsd->cvc, hellomsg->cvc, 32);
	crypto_from_eddsa_public(hsd->ikc, hellomsg->iskc);
	memcpy(hsd->ekc, hellomsg->ekc, 32);
	memcpy(hsd->iskc, hellomsg->iskc, 32);

	return 0;
}

void
mesg_hshake_dreply(struct mesg_state *state, uint8_t buf[MESG_REPLY_SIZE])
{
	struct mesg_hshake_dstate *hsd = &state->u.hsd;
	struct mesg_ratchet_dstate *rad = &state->u.rad;
	struct mesg_ratchet_state_common *ra = &state->u.rad.rac;
	struct hshake_reply_msg *replymsg = (struct hshake_reply_msg *)buf;
	uint8_t dh[128];
	uint8_t iskc[32], ikc[32], ikd[32], ekd_prv[32];

	memcpy(replymsg->eks, hsd->ekd, 32);
	memcpy(replymsg->cvs, hsd->cvd, 32);

	crypto_lock(
		replymsg->mac,
		replymsg->eks,
		hsd->shared,
		zero_nonce,
		replymsg->eks,
		MESG_REPLY_SIZE - offsetof(struct hshake_reply_msg, eks));

	crypto_x25519(dh,      hsd->ikd_prv, hsd->ikc);
	crypto_x25519(dh + 32, hsd->ikd_prv, hsd->ekc);
	crypto_x25519(dh + 64, hsd->ekd_prv, hsd->ikc);
	crypto_x25519(dh + 96, hsd->ekd_prv, hsd->ekc);

	memcpy(iskc,    hsd->iskc,    32);
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
	memcpy(rad->iskc,    iskc,          32);

	crypto_wipe(iskc,    32);
	crypto_wipe(ikc,     32);
	crypto_wipe(ikd,     32);
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
	struct mesg_ratchet_state_common *ra = &state->u.ra.rac;
	struct hshake_reply_msg *replymsg = (struct hshake_reply_msg *)buf;
	uint8_t dh_hs[128];
	uint8_t dh_ra[32];
	uint8_t ikc[32], ikd[32];
	int result = -1;

	if (try_decrypt_reply(hsc, replymsg))
		goto end;

	crypto_x25519(dh_hs,      hsc->ikc_prv, hsc->ikd);
	crypto_x25519(dh_hs + 32, hsc->ekc_prv, hsc->ikd);
	crypto_x25519(dh_hs + 64, hsc->ikc_prv, replymsg->eks);
	crypto_x25519(dh_hs + 96, hsc->ekc_prv, replymsg->eks);

	memcpy(ikc, hsc->ikc, 32);
	memcpy(ikd, hsc->ikd, 32);

	/* switch from hshake state to ratchet state */
	crypto_wipe(state, sizeof(struct mesg_state));

	hshake_compute_shared_secrets(ra->rk, ra->nhkr, ra->hks, dh_hs);
	generate_kex_keypair(ra->dhks, ra->dhks_prv);
	memcpy(ra->ad,      ikc,           32);
	memcpy(ra->ad + 32, ikd,           32);
	memcpy(ra->cv,      replymsg->cvs, 32);

	crypto_x25519(dh_ra, ra->dhks_prv, replymsg->eks);
	dh_ratchet(ra->rk, ra->cks, ra->nhks, dh_ra);
	result = 0;

end:	crypto_wipe(ikc,    32);
	crypto_wipe(dh_ra,  32);
	crypto_wipe(dh_hs, 128);

	return result;
}

static
void
offline_shared_secrets(uint8_t sk[32], uint8_t nhk[32], uint8_t hk[32],
		uint8_t *dh, size_t dh_size)
{
	uint8_t tmp[96 + sizeof(ohs_info) + 1];

	hkdf_blake2b(
		tmp,      96,
		NULL,     0,
		ohs_info, sizeof(ohs_info),
		dh,       dh_size);

	memcpy(sk,  tmp,      32);
	memcpy(hk,  tmp + 32, 32);
	memcpy(nhk, tmp + 64, 32);

	crypto_wipe(dh, dh_size);
	crypto_wipe(tmp, 96);
}

int
mesg_hshake_aprepare(struct mesg_state *state,
	const uint8_t ika[32], const uint8_t ika_prv[32],
	const uint8_t iskb[32], const uint8_t ikb[32],
	const uint8_t spkb[32], const uint8_t spkb_sig[64],
	const uint8_t opkb[32])
{
	struct mesg_ratchet_astate_prerecv *rap = &state->u.rap;
	struct mesg_ratchet_state_common *ra = &rap->rac;
	uint8_t dh[128];
	uint8_t hk[32];
	uint8_t eka_prv[32];

	if (check_key(iskb, "AIBS", spkb, spkb_sig))
		return -1;

	generate_kex_keypair(rap->eka, eka_prv);

	rap->rac.prerecv = 1;
	memcpy(rap->ika,  ika,  32);
	memcpy(rap->spkb, spkb, 32);
	memcpy(rap->opkb, opkb, 32);

	crypto_x25519(dh,      ika_prv, spkb);
	crypto_x25519(dh + 32, eka_prv, ikb);
	crypto_x25519(dh + 64, eka_prv, spkb);
	if (!crypto_verify32(opkb, zero_key)) {
		offline_shared_secrets(ra->rk, ra->nhkr, ra->hks, dh, 96);
	} else {
		crypto_x25519(dh + 96, eka_prv, opkb);
		offline_shared_secrets(ra->rk, ra->nhkr, ra->hks, dh, 128);
	}
	crypto_wipe(eka_prv, 32);

	generate_kex_keypair(ra->dhks, ra->dhks_prv);
	memcpy(ra->ad,      ika, 32);
	memcpy(ra->ad + 32, ikb, 32);

	crypto_x25519(dh, ra->dhks_prv, spkb);
	dh_ratchet(ra->rk, ra->cks, ra->nhks, dh);
	crypto_wipe(dh, 32);

	simple_key_exchange(hk, ika_prv, ikb, ika, ikb);
	memcpy(rap->hk, hk, 32);
	crypto_wipe(hk, 32);

	return 0;
}

void
mesg_hshake_ahello(struct mesg_state *state, uint8_t *buf, size_t msgsize)
{
	struct hshake_ohello_msg *msg = (struct hshake_ohello_msg *)buf;
	struct mesg_ratchet_astate_prerecv *rap = &state->u.rap;

	msg->msgtype = 0;
	memcpy(msg->eka, rap->eka, 32);
	memcpy(msg->spkb, rap->spkb, 32);
	memcpy(msg->opkb, rap->opkb, 32);
	randbytes(msg->nonce, 24);
	crypto_lock(msg->mac,
		&msg->msgtype,
		rap->hk,
		msg->nonce,
		&msg->msgtype,
		sizeof(struct hshake_ohello_msg) - offsetof(struct hshake_ohello_msg, msgtype));
	mesg_lock(state, msg->message, msgsize);
}

size_t
send_ohello_message(struct mesg_state *state, struct mesg_state *p2pstate,
		uint8_t recipient_isk[32], uint8_t *buf,
		const uint8_t *text, size_t text_size)
{
	struct msg_forward_msg *msg = (void *)MESG_TEXT(buf);
	uint8_t *smsg = MESG_TEXT(buf) + MSG_FORWARD_MSG_BASE_SIZE + 2; /* start of encapsulated message */
	uint8_t *cbuf = smsg + MESG_P2PHELLO_SIZE(0); /* start of internal message */
	uint8_t *ctext = MESG_TEXT(cbuf);
	uint16_t msglength;

	/* actual peer-to-peer message */
	if (text != NULL) {
		memcpy(ctext + 2, text, text_size);
	}
	store16_le(ctext, text_size);

	msglength = padme_enc(MESG_P2PHELLO_SIZE(2 + text_size)) - MESG_P2PHELLO_SIZE(0);
	store16_le(cbuf - 2, MESG_BUF_SIZE(msglength));
	mesg_hshake_ahello(p2pstate, smsg, msglength);

	/* message-forwarding message to server */
	msg->msg.proto = PROTO_MSG;
	msg->msg.type = MSG_FORWARD_MSG;
	memcpy(msg->isk, recipient_isk, 32);
	msg->message_count = 1;
	store16_le(msg->messages, MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength)));

	{
		uint16_t msgsize = padme_enc(MSG_FORWARD_MSG_SIZE(2 + MESG_P2PHELLO_SIZE(MESG_BUF_SIZE(msglength))));
		mesg_lock(state, buf, msgsize);
		return msgsize;
	}
}

size_t
send_omsg_message(struct mesg_state *state, struct mesg_state *p2pstate,
		uint8_t recipient_isk[32], uint8_t *buf,
		const uint8_t *text, size_t text_size)
{
	struct msg_forward_msg *msg = (void *)MESG_TEXT(buf);
	uint8_t *cbuf = MESG_TEXT(buf) + MSG_FORWARD_MSG_BASE_SIZE + 2; /* start of internal message */
	uint8_t *ctext = MESG_TEXT(cbuf);
	uint16_t msglength;

	/* actual peer-to-peer message */
	if (text != NULL) {
		memcpy(ctext + 2, text, text_size);
	}
	store16_le(ctext, text_size);
	msglength = padme_enc(text_size + 2);
	mesg_lock(p2pstate, cbuf, msglength);

	/* message-forwarding message to server */
	msg->msg.proto = PROTO_MSG;
	msg->msg.type = MSG_FORWARD_MSG;
	store16_le(msg->msg.len, MSG_FORWARD_MSG_SIZE(2 + MESG_BUF_SIZE(msglength)));
	memcpy(msg->isk, recipient_isk, 32);
	msg->message_count = 1;
	store16_le(msg->messages, MESG_BUF_SIZE(msglength));

	{
		uint16_t msgsize = padme_enc(MSG_FORWARD_MSG_SIZE(2 + MESG_BUF_SIZE(msglength)));
		mesg_lock(state, buf, msgsize);
		return msgsize;
	}
}

size_t
send_message(struct mesg_state *state, struct mesg_state *p2pstate,
		uint8_t recipient_isk[32], uint8_t *buf,
		const uint8_t *text, size_t text_size)
{
	/* fprintf(stderr, "prerecv? %d\n", p2pstate->u.ra.rac.prerecv); */
	return (p2pstate->u.ra.rac.prerecv ? send_ohello_message : send_omsg_message)
		(state, p2pstate, recipient_isk, buf, text, text_size);
}

#if 0
int
mesg_example1(int fd)
{
	/* uint8_t iska[32], iska_prv[32]; */
	uint8_t ika[32], ika_prv[64];
	/* obtained from server */
	uint8_t iskb[32];
	/* uint8_t ikb[32], ikb_sig[64]; */
	uint8_t spkb[32], spkb_sig[64];
	uint8_t opkb[32];
	uint8_t buf[65536];
	struct mesg_state state;

	/* Prepare the message state for the first handshake message */
	if (mesg_hshake_aprepare(&state,
			ika, ika_prv,
			iskb, ikb, /*ikb_sig,*/ spkb, spkb_sig, opkb))
		return -1;

	/* Create the P2PHELLO (OFFLINE-HELLO) message and update state */
	mesg_hshake_ahello(&state, buf, 0);

	/* Write the P2PHELLO message out to a socket */
	(void)!write(fd, buf, MESG_P2PHELLO_SIZE(0));

	/* Wipe the P2PHELLO message now it has been sent */
	crypto_wipe(buf, MESG_P2PHELLO_SIZE(0));

	return 0;
}

int
mesg_example2(int fd __attribute__((unused)))
{
	return -1;
}

int
mesg_example3(int fd)
{
	/* These need to be obtained somehow */
	uint8_t server_sig_public_key[32];
	uint8_t server_kex_public_key[32];
	/* In reality these are long-term keys, not generated every time. */
	uint8_t sign_public_key[32], sign_private_key[32];
	uint8_t kex_public_key[32], kex_private_key[32];
	struct mesg_state state;

	memcpy(server_sig_public_key, isks, 32);
	(void)isks_prv;
	memcpy(server_kex_public_key, iks, 32);
	(void)iks_prv;

	generate_sig_keypair(sign_public_key, sign_private_key);
	generate_kex_keypair(kex_public_key, kex_private_key);

	{
		uint8_t buf[MESG_HSHAKE_SIZE];

		/* Prepare the message state for the first handshake message */
		mesg_hshake_cprepare(&state,
			server_sig_public_key, server_kex_public_key,
			sign_public_key, sign_private_key,
			kex_public_key, kex_private_key);

		/* Create the HELLO message and update state */
		mesg_hshake_chello(&state, buf);

		/* Write the hello message out to a socket */
		(void)!write(fd, buf, MESG_HELLO_SIZE);

		/* Wipe the hello message now it has been sent */
		crypto_wipe(buf, MESG_HELLO_SIZE);

		/* Read a reply back from the peer */
		(void)!read(fd, buf, MESG_REPLY_SIZE);

		/* Check the handshake reply's integrity and update state */
		if (mesg_hshake_cfinish(&state, buf)) {
			crypto_wipe(buf, MESG_REPLY_SIZE);
			return -1;
		}
		
		/* Wipe the reply message now it has been checked */
		crypto_wipe(buf, MESG_REPLY_SIZE);
	}

	return 0;
}

int
mesg_example4(int fd)
{
	/* In reality these are long-term keys, not generated every time. */
	uint8_t sign_public_key[32], sign_private_key[32];
	uint8_t kex_public_key[32], kex_private_key[32];
	struct mesg_state state;

	generate_sig_keypair(sign_public_key, sign_private_key);
	generate_kex_keypair(kex_public_key, kex_private_key);

	/* Prepare the message state as an online handshake replier */
	mesg_hshake_dprepare(&state,
		sign_public_key, sign_private_key,
		kex_public_key, kex_private_key);

	{
		uint8_t buf[MESG_HSHAKE_SIZE];

		/* Read a hello message from a peer */
		(void)!read(fd, buf, MESG_HELLO_SIZE);

		/* Check the handshake hello and update state */
		if (mesg_hshake_dcheck(&state, buf)) {
			crypto_wipe(buf, MESG_HELLO_SIZE);
			return -1;
		}

		/* Wipe the hello message now it has been checked */
		crypto_wipe(buf, MESG_HELLO_SIZE);

		/* Create the reply message and update state */
		mesg_hshake_dreply(&state, buf);

		/* Write the reply message out to the socket */
		(void)!write(fd, buf, MESG_REPLY_SIZE);

		/* Wipe the reply message now it has been sent */
		crypto_wipe(buf, MESG_REPLY_SIZE);
	}

	return 0;
}
#endif
