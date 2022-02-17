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
#include "ident.h"
#include "mesg.h"
#include "hkdf.h"
#include "monocypher.h"

#define MAX_SKIP 1000
#define AD_SIZE  64

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
try_decrypt_header(const struct mesg_ratchet_state_common *ra,
		uint8_t hk[32], struct mesghdr *hdr)
{
	int result;

	/* displaykey_short("hk", hk, 32); */
	/* displaykey_short("nonce", hdr->nonce, 24); */
	/* displaykey_short("hdrmac", hdr->hdrmac, 16); */
	/* displaykey_short("ra->ad", ra->ad, AD_SIZE); */

	result = crypto_unlock_aead(
		hdr->msn,
		hk,
		hdr->nonce,
		hdr->hdrmac,
		ra->ad,
		AD_SIZE,
		hdr->msn,
		sizeof(struct mesghdr) - offsetof(struct mesghdr, msn));

	/* fprintf(stderr, "try_decrypt_header: %d\n", result); */
	/* displaykey("hdr", (void *)hdr, sizeof(struct mesghdr)); */

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

static
int
try_skipped_message_keys(struct mesg_ratchet_state_common *ra, struct mesg *mesg, size_t mesg_size)
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
			if (decrypt_message(mesgkey->mk, mesg, mesg_size, ra->ad))
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
	int result;

	if (!try_skipped_message_keys(ra, mesg, mesg_size))
		return 0;

	if (try_decrypt_header(ra, ra->hkr, &mesg->hdr)) {
		if (try_decrypt_header(ra, ra->nhkr, &mesg->hdr))
			return -1;
		if (skip_message_keys(ra, load32_le(mesg->hdr.pn)))
			return -1;
		step_receiver_ratchet(ra, &mesg->hdr);
	}
	if (skip_message_keys(ra, load32_le(mesg->hdr.msn)))
		return -1;

	symm_ratchet(mk, ra->ckr);
	ra->nr++;

	result = decrypt_message(mk, mesg, mesg_size, ra->ad);
	crypto_wipe(mk, 32);
	return result;
}

static
void
encrypt_message(struct mesg_ratchet_state_common *ra, struct mesg *mesg, size_t mesg_size)
{
	uint8_t mk[32];

	symm_ratchet(mk, ra->cks);

	/* displaykey_short("dhkr",     ra->dhkr,     32); */
	/* displaykey_short("dhks",     ra->dhks,     32); */
	/* displaykey_short("dhks_prv", ra->dhks_prv, 32); */
	/* displaykey_short("rk",       ra->rk,       32); */
	/* displaykey_short("cks",      ra->cks,      32); */
	/* displaykey_short("ckr",      ra->ckr,      32); */
	/* displaykey_short("hks",      ra->hks,      32); */
	/* displaykey_short("hkr",      ra->hkr,      32); */
	/* displaykey_short("nhks",     ra->nhks,     32); */
	/* displaykey_short("nhkr",     ra->nhkr,     32); */
	/* displaykey_short("ad",       ra->ad,       64); */
	/* displaykey_short("cv",       ra->cv,       32); */
	/* fprintf(stderr, "ns:\t%u\n", ra->ns); */
	/* fprintf(stderr, "nr:\t%u\n", ra->nr); */
	/* fprintf(stderr, "pn:\t%u\n", ra->pn); */

	store32_le(mesg->hdr.msn, ra->ns);
	store32_le(mesg->hdr.pn, ra->pn);
	memcpy(mesg->hdr.pk, ra->dhks, 32);

	crypto_lock_aead(
		mesg->hdr.mac,
		mesg->text,
		mk,
		zero_nonce, /* (each message is sent using a one-use secret key,
		                so AEAD can use a constant nonce)
			       (perhaps this should be some other constant to
				provide domain separation?)*/
		ra->ad,
		AD_SIZE,
		mesg->text,
		mesg_size);

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

	/* displaykey_short("hk", ra->hks, 32); */
	/* displaykey_short("nonce", mesg->hdr.nonce, 24); */
	/* displaykey_short("hdrmac", mesg->hdr.hdrmac, 16); */
	/* displaykey_short("ra->ad", ra->ad, AD_SIZE); */

	/* displaykey("hdr", (void *)&mesg->hdr, sizeof(struct mesghdr)); */

	crypto_wipe(mk, 32);

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
	encrypt_message(&state->u.ra.rac, (struct mesg *)buf, text_size);
}

int
mesg_unlock(struct mesg_state *state, uint8_t *buf, size_t buf_size)
{
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
	/* crypto_from_eddsa_public(hsc->ikc, iskc); (void)ikc; */
	memcpy(hsc->ikc_prv, ikc_prv,  32);
	/* crypto_from_eddsa_private(hsc->ikc_prv, iskc_prv); (void)ikc_prv; */
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
	/* memcpy(hellomsg->ikc,    hsc->ikc,  32); */
	memcpy(hellomsg->ekc,    hsc->ekc,  32);
	memcpy(hellomsg->cvc,    hsc->cvc,  32);
	/* sign_key(hellomsg->ikc_sig, hsc->iskc_prv, hsc->iskc, "AHCI", hsc->ikc); */
	sign_key(hellomsg->ekc_sig, hsc->iskc_prv, hsc->iskc, "AHCE", hsc->ekc);

	/* encrypt the hello message */
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

	crypto_x25519(dh,      spkb_prv, ika);
	crypto_x25519(dh + 32, ikb_prv,  eka);
	crypto_x25519(dh + 64, spkb_prv, eka);

	if (crypto_verify32(opkb, zero_key)) {
		offline_shared_secrets(ra->rk, ra->nhks, ra->nhkr, dh, 96);
	} else {
		crypto_x25519(dh + 96, opkb_prv, eka);
		offline_shared_secrets(ra->rk, ra->nhks, ra->nhkr, dh, 96);
	}

	memcpy(ra->dhks,     spkb,     32);
	memcpy(ra->dhks_prv, spkb_prv, 32);
	memcpy(ra->ad,       ika,      32);
	memcpy(ra->ad + 32,  ikb,      32);
}

int
mesg_hshake_bfinish(struct mesg_state *state, uint8_t *buf, size_t size)
{
	return mesg_unlock(state, buf, MESG_BUF_SIZE(size));
}

/* static */
/* int */
/* try_decrypt_ohello(struct mesg_hshake_bstate *hsb, struct hshake_ohello_msg *ohellomsg) */
/* { */
/* 	uint8_t hk[32]; */
/* 	uint8_t dh[128]; */
/* 	uint8_t ika[32]; */
/* 	int result; */

/* 	crypto_from_eddsa_public(ika,      hsb->iska); */
/* 	crypto_x25519(dh,      hsb->spkb_prv, ika); */
/* 	crypto_x25519(dh + 32, hsb->ikb_prv,  hsb->eka); */
/* 	crypto_x25519(dh + 64, hsb->spkb_prv, hsb->eka); */

/* 	if (crypto_verify32(hsb->opkb, zero_key)) { */
/* 		offline_shared_secrets(ra->rk, ra->nhkr, ra->hks, dh, 96); */
/* 		crypto_wipe(dh, 96); */
/* 	} else { */
/* 		crypto_x25519(dh + 96, opkb_prv, hsb->eka); */
/* 		offline_shared_secrets(ra->rk, ra->nhkr, ra->hks, dh, 128); */
/* 		crypto_wipe(dh, 128); */
/* 	} */

/* 	crypto_hidden_to_curve(hellomsg->hidden, hellomsg->hidden); */
/* 	hello_compute_shared_secrets(hellokey, hsd->shared, hsd->ikd_prv, hellomsg->hidden); */
/* 	result = crypto_unlock( */
/* 		hellomsg->iskc, */
/* 		hellokey, */
/* 		zero_nonce, */
/* 		hellomsg->mac, */
/* 		hellomsg->iskc, */
/* 		MESG_HELLO_SIZE - offsetof(struct hshake_hello_msg, iskc)); */

/* 	crypto_wipe(hellokey, 32); */

/* 	return result; */
/* } */

/* int */
/* mesg_hshake_bcheck(struct mesg_state *state, uint8_t *buf) */
/* { */
/* 	struct mesg_hshake_bstate *hsb = &state->u.hsb; */
/* 	struct mesg_ratchet_state_common *ra = &state->u.ra; */
/* 	struct hshake_ohello_msg *ohellomsg = (struct hshake_ohello_msg *)buf; */

/* 	if (try_decrypt_ohello(hsb, ohellomsg)) */
/* 		return -1; */
/* } */

/* int */
/* mesg_hshake_breply(struct mesg_state *state) */
/* { */

/* } */


int
mesg_hshake_dcheck(struct mesg_state *state, uint8_t buf[MESG_HELLO_SIZE])
{
	struct mesg_hshake_dstate *hsd = &state->u.hsd;
	struct hshake_hello_msg *hellomsg = (struct hshake_hello_msg *)buf;

	if (try_decrypt_hello(hsd, hellomsg))
		return -1;
	/* if (check_key(hellomsg->iskc, "AHCI", hellomsg->ikc, hellomsg->ikc_sig)) */
	/* 	return -1; */
	if (check_key(hellomsg->iskc, "AHCE", hellomsg->ekc, hellomsg->ekc_sig))
		return -1;

	memcpy(hsd->cvc, hellomsg->cvc, 32);
	/* memcpy(hsd->ikc, hellomsg->ikc, 32); */
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

	if (check_key(hsc->iskd, "AHDE", replymsg->eks, replymsg->eks_sig))
		goto end;
	if (check_key(hsc->iskd, "AHDC", hsc->cvc,      replymsg->cvc_sig))
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
	const uint8_t iskb[32],
	const uint8_t ikb[32], /*const uint8_t ikb_sig[64],*/
	const uint8_t spkb[32], const uint8_t spkb_sig[64],
	const uint8_t opkb[32])
{
	struct mesg_ratchet_astate_prerecv *rap = &state->u.rap;
	struct mesg_ratchet_state_common *ra = &rap->rac;
	uint8_t dh[128];
	uint8_t hk[32];
	uint8_t eka_prv[32];

	/* if (check_key(iskb, "AIBI", ikb, ikb_sig)) { */
	/* 	fprintf(stderr, "AIBI\n"); */
	/* 	return -1; */
	/* } */
	if (check_key(iskb, "AIBS", spkb, spkb_sig)) {
		fprintf(stderr, "AIBS\n");
		return -1;
	}

	/* generate_hidden_keypair(rap->eka, eka_prv); */
	generate_kex_keypair(rap->eka, eka_prv);

	memcpy(rap->ika,  ika,  32);
	memcpy(rap->spkb, spkb, 32);
	memcpy(rap->opkb, opkb, 32);

	displaykey("ikaprv", ika_prv, 32);
	displaykey("ekaprv", eka_prv, 32);
	displaykey("spkb", spkb, 32);
	displaykey("ikb", ikb, 32);
	displaykey("opkb", opkb, 32);
	crypto_x25519(dh,      ika_prv, spkb);
	crypto_x25519(dh + 32, eka_prv, ikb);
	crypto_x25519(dh + 64, eka_prv, spkb);
	if (crypto_verify32(opkb, zero_key)) {
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
	fprintf(stderr, "Encrypting message of size %lu\n", msgsize);
	mesg_lock(state, msg->message, msgsize);
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
