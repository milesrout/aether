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

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "queue.h"
#include "packet.h"
#include "msg.h"
#include "util.h"
#include "ident.h"
#include "chat.h"
#include "hkdf.h"
#include "monocypher.h"
#include "persist.h"

#define MAX_SKIP 1000
#define AD_SIZE  64
#define AAD_SIZE 104

/* prepares the message by advancing the state machine, preparing the header,
 * encryping the message in place and then encrypting the header in place.
 * the resulting struct packet is ready to be sent over the wire.
 *
 * packet must point to the message to be prepared. if anything is to be done to
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

static SLIST_HEAD(ssbh, packetkey_bucket) spare_buckets =
	SLIST_HEAD_INITIALIZER(spare_buckets);
static SLIST_HEAD(ssph, packetkey) spare_packetkeys =
	SLIST_HEAD_INITIALIZER(spare_packetkeys);

size_t
padme_enc(size_t l)
{
	return PACKET_TEXT_SIZE(padme(PACKET_BUF_SIZE(l)));
}

void
packet_get_iskc(uint8_t iskc[32], const union packet_state *state)
{
	memcpy(iskc, state->rad.iskc, 32);
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
 * packet should be a struct packet that has NOT had its header decrypted
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
try_decrypt_header(const struct packet_ratchet_state_common *ra,
		uint8_t hk[32], struct packethdr *hdr)
{
	return crypto_unlock_aead(
		hdr->msn,
		hk,
		hdr->nonce,
		hdr->hdrmac,
		ra->ad,
		AD_SIZE,
		hdr->msn,
		sizeof(struct packethdr) - offsetof(struct packethdr, msn));
}

/* decrypt a partially decrypted message
 * packet should be a struct packet that has had its header decrypted
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
decrypt_message(uint8_t mk[32], struct packet *packet, size_t packet_size,
		const uint8_t *aad, size_t aad_size)
{
	int result;

	result = crypto_unlock_aead(
		packet->text,
		mk,
		zero_nonce,
		packet->hdr.mac,
		aad,
		aad_size,
		packet->text,
		packet_size);

	if (!result)
		crypto_wipe(mk, 32);

	return result;
}

static
int
try_skipped_message_keys(struct packet_ratchet_state_common *ra,
	struct packet *packet, size_t packet_size,
	const uint8_t *aad, size_t aad_size)
{
	struct packetkey_bucket *prev_bucket, *bucket;
	struct packetkey *prev_packetkey, *packetkey;

	prev_bucket = NULL;
	bucket = SLIST_FIRST(&ra->skipped);

	while (bucket != NULL) {

		if (try_decrypt_header(ra, bucket->hk, &packet->hdr)) {
			goto outer_continue;
		}

		prev_packetkey = NULL;
		packetkey = SLIST_FIRST(&bucket->bucket);

		while (packetkey != NULL) {

			if (packetkey->msn != load32_le(packet->hdr.msn)) {
				goto inner_continue;
			}

			/* header decrypted and the correct msn */

			/* attempt to decrypt the message */
			if (decrypt_message(packetkey->mk, packet, packet_size, aad, aad_size))
				return -1;

			/* if successful, remove the struct packetkey from the
			 * bucket and remove the bucket from the bucket list if
			 * it is now empty.
			 */
			
			if (prev_packetkey != NULL) {
				SLIST_REMOVE_AFTER(prev_packetkey, bucket);
				goto detach_packetkey;
			}

			if (SLIST_NEXT(packetkey, bucket) != NULL) {
				SLIST_REMOVE_HEAD(&bucket->bucket, bucket);
				goto detach_packetkey;
			}

			if (prev_bucket != NULL) {
				SLIST_REMOVE_AFTER(prev_bucket, buckets);
				goto detach_bucket;
			}

			if (SLIST_NEXT(bucket, buckets) != NULL) {
				SLIST_REMOVE_HEAD(&ra->skipped, buckets);
				goto detach_bucket;
			}

		detach_bucket:
			crypto_wipe(bucket, sizeof(struct packetkey_bucket));
			SLIST_INSERT_HEAD(&ra->spare_buckets, bucket, buckets);
		detach_packetkey:
			crypto_wipe(packetkey, sizeof(struct packetkey));
			SLIST_INSERT_HEAD(&ra->spare_packetkeys, packetkey, bucket);
			return 0;

		inner_continue:
			prev_packetkey = packetkey;
			packetkey = SLIST_NEXT(packetkey, bucket);
		}
	outer_continue:
		prev_bucket = bucket;
		bucket = SLIST_NEXT(bucket, buckets);
	}

	return -1;
}

struct packetkey_bucket *
bucket_create(struct packet_ratchet_state_common *ra)
{
	struct packetkey_bucket *b;

	if (ra && !SLIST_EMPTY(&ra->spare_buckets)) {
		b = SLIST_FIRST(&ra->spare_buckets);
		SLIST_REMOVE_HEAD(&ra->spare_buckets, buckets);
		return b;
	}

	if (!SLIST_EMPTY(&spare_buckets)) {
		b = SLIST_FIRST(&spare_buckets);
		SLIST_REMOVE_HEAD(&spare_buckets, buckets);
		return b;
	}

	return malloc(sizeof *b);
}

struct packetkey *
packetkey_create(struct packet_ratchet_state_common *ra)
{
	struct packetkey *m;

	if (ra && !SLIST_EMPTY(&ra->spare_packetkeys)) {
		m = SLIST_FIRST(&ra->spare_packetkeys);
		SLIST_REMOVE_HEAD(&ra->spare_packetkeys, bucket);
		return m;
	}

	if (!SLIST_EMPTY(&spare_packetkeys)) {
		m = SLIST_FIRST(&spare_packetkeys);
		SLIST_REMOVE_HEAD(&spare_packetkeys, bucket);
		return m;
	}

	return malloc(sizeof *m);
}

static
int
skip_message_keys_helper(struct packet_ratchet_state_common *ra, uint32_t until)
{
	struct packetkey *prev_packetkey = NULL;
	struct packetkey_bucket *bucket;

	bucket = bucket_create(ra);
	if (bucket == NULL)
		return -1;

	memcpy(bucket->hk, ra->hkr, 32);
	SLIST_INSERT_HEAD(&ra->skipped, bucket, buckets);

	while (ra->nr < until) {
		struct packetkey *packetkey = packetkey_create(ra);

		if (packetkey == NULL)
			return -1;

		if (prev_packetkey == NULL)
			SLIST_INSERT_HEAD(&bucket->bucket, packetkey, bucket);
		else
			SLIST_INSERT_AFTER(prev_packetkey, packetkey, bucket);
		prev_packetkey = packetkey;

		packetkey->msn = ra->nr;
		symm_ratchet(packetkey->mk, ra->ckr);

		ra->nr++;
	}

	return 0;
}

static
int
skip_message_keys(struct packet_ratchet_state_common *ra, uint32_t until)
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
step_receiver_ratchet(struct packet_ratchet_state_common *ra, struct packethdr *hdr)
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
try_decrypt_message(struct packet_ratchet_state_common *ra, struct packet *packet, size_t packet_size)
{
	uint8_t mk[32];
	uint8_t aad[AAD_SIZE];
	int result = -1;

	memcpy(aad,      ra->ad,          64);
	memcpy(aad + 64, packet->hdr.msn, 4);
	memcpy(aad + 68, packet->hdr.pn,  4);
	memcpy(aad + 72, packet->hdr.pk,  32);

	if (!try_skipped_message_keys(ra, packet, packet_size, aad, AAD_SIZE)) {
		crypto_wipe(aad, AAD_SIZE);
		return 0;
	}

	if (try_decrypt_header(ra, ra->hkr, &packet->hdr)) {
		if (try_decrypt_header(ra, ra->nhkr, &packet->hdr))
			goto fail;
		if (skip_message_keys(ra, load32_le(packet->hdr.pn)))
			goto fail;
		step_receiver_ratchet(ra, &packet->hdr);
	}
	if (skip_message_keys(ra, load32_le(packet->hdr.msn)))
		goto fail;

	symm_ratchet(mk, ra->ckr);
	ra->nr++;

	result = decrypt_message(mk, packet, packet_size, aad, AAD_SIZE);
	if (!result)
		ra->prerecv = 0;
fail:
	crypto_wipe(mk, 32);
	crypto_wipe(aad, AAD_SIZE);
	return result;
}

static
void
encrypt_message(struct packet_ratchet_state_common *ra, struct packet *packet, size_t packet_size)
{
	uint8_t mk[32];
	uint8_t aad[AAD_SIZE];

	symm_ratchet(mk, ra->cks);

	store32_le(packet->hdr.msn, ra->ns);
	store32_le(packet->hdr.pn, ra->pn);
	memcpy(packet->hdr.pk, ra->dhks, 32);

	randbytes(packet->hdr.nonce, 24);

	crypto_lock_aead(
		packet->hdr.hdrmac,
		packet->hdr.msn,
		ra->hks,
		packet->hdr.nonce,
		ra->ad,
		AD_SIZE,
		packet->hdr.msn,
		sizeof(struct packethdr) - offsetof(struct packethdr, msn));

	memcpy(aad,      ra->ad,          64);
	memcpy(aad + 64, packet->hdr.msn, 4);
	memcpy(aad + 68, packet->hdr.pn,  4);
	memcpy(aad + 72, packet->hdr.pk,  32);

	crypto_lock_aead(
		packet->hdr.mac,
		packet->text,
		mk,
		zero_nonce, /* (each message is sent using a one-use secret key,
		                so AEAD can use a constant nonce)
			       (perhaps this should be some other constant to
				provide domain separation?)*/
		aad,
		AAD_SIZE,
		packet->text,
		packet_size);

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
packet_lock(union packet_state *state, uint8_t *buf, size_t text_size)
{
	encrypt_message(&state->ra.rac, (struct packet *)buf, text_size);
}

int
packet_unlock(union packet_state *state, uint8_t *buf, size_t buf_size)
{
	return try_decrypt_message(&state->ra.rac,
		(struct packet *)buf, buf_size - sizeof(struct packet));
}

void
packet_hshake_dprepare(union packet_state *state,
		const uint8_t iskd[32], const uint8_t iskd_prv[32],
		const uint8_t ikd[32], const uint8_t ikd_prv[32],
		const uint8_t cvd[32])
{
	struct packet_hshake_dstate *hsd = &state->hsd;

	crypto_wipe(state, sizeof *state);

	memcpy(hsd->iskd,    iskd,     32);
	memcpy(hsd->iskd_prv,iskd_prv, 32);
	memcpy(hsd->ikd,     ikd,      32);
	memcpy(hsd->ikd_prv, ikd_prv,  32);
	generate_kex_keypair(hsd->ekd, hsd->ekd_prv);
	if (cvd == NULL)
		randbytes(hsd->cvd, 32);
	else
		memcpy(hsd->cvd, cvd, 32);
}

void
packet_hshake_cprepare(union packet_state *state,
		const uint8_t iskd[32], const uint8_t ikd[32],
		const uint8_t iskc[32], const uint8_t iskc_prv[32],
		const uint8_t ikc[32], const uint8_t ikc_prv[32],
		const uint8_t cvc[32])
{
	struct packet_hshake_cstate *hsc = &state->hsc;

	crypto_wipe(state, sizeof *state);

	memcpy(hsc->iskd,    iskd,     32);
	memcpy(hsc->ikd,     ikd,      32);
	memcpy(hsc->iskc,    iskc,     32);
	memcpy(hsc->iskc_prv,iskc_prv, 32);
	memcpy(hsc->ikc,     ikc,      32);
	memcpy(hsc->ikc_prv, ikc_prv,  32);
	generate_kex_keypair(hsc->ekc, hsc->ekc_prv);
	generate_hidden_keypair(hsc->hkc, hsc->hkc_prv);
	if (cvc == NULL)
		randbytes(hsc->cvc, 32);
	else
		memcpy(hsc->cvc, cvc, 32);
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
packet_hshake_chello(union packet_state *state, uint8_t buf[PACKET_HELLO_SIZE])
{
	struct packet_hshake_cstate *hsc = &state->hsc;
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
try_decrypt_hello(struct packet_hshake_dstate *hsd, struct hshake_hello_msg *hellomsg)
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
		PACKET_HELLO_SIZE - offsetof(struct hshake_hello_msg, iskc));

	crypto_wipe(hellokey, 32);

	return result;
}

void
packet_hshake_bprepare(union packet_state *state,
	const uint8_t ika[32], const uint8_t eka[32],
	const uint8_t ikb[32],  const uint8_t ikb_prv[32],
	const uint8_t spkb[32], const uint8_t spkb_prv[32],
	const uint8_t opkb[32], const uint8_t opkb_prv[32])
{
	struct packet_ratchet_state_common *ra = &state->ra.rac;
	uint8_t dh[128];

	crypto_wipe(state, sizeof *state);

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
packet_hshake_bfinish(union packet_state *state, uint8_t *buf, size_t size)
{
	return packet_unlock(state, buf, size);
}

int
packet_hshake_dcheck(union packet_state *state, uint8_t buf[PACKET_HELLO_SIZE])
{
	struct packet_hshake_dstate *hsd = &state->hsd;
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
packet_hshake_dreply(union packet_state *state, uint8_t buf[PACKET_REPLY_SIZE])
{
	struct packet_hshake_dstate *hsd = &state->hsd;
	struct packet_ratchet_dstate *rad = &state->rad;
	struct packet_ratchet_state_common *ra = &state->rad.rac;
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
		PACKET_REPLY_SIZE - offsetof(struct hshake_reply_msg, eks));

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
try_decrypt_reply(struct packet_hshake_cstate *hsc, struct hshake_reply_msg *replymsg)
{
	int result;

	result = crypto_unlock(
		replymsg->eks,
		hsc->shared,
		zero_nonce,
		replymsg->mac,
		replymsg->eks,
		PACKET_REPLY_SIZE - offsetof(struct hshake_reply_msg, eks));

	if (!result)
		crypto_wipe(hsc->shared, 32);

	return result;
}

int
packet_hshake_cfinish(union packet_state *state, uint8_t buf[PACKET_REPLY_SIZE])
{
	struct packet_hshake_cstate *hsc = &state->hsc;
	struct packet_ratchet_state_common *ra = &state->ra.rac;
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
	crypto_wipe(state, sizeof(union packet_state));

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
packet_hshake_aprepare(union packet_state *state,
	const uint8_t ika[32], const uint8_t ika_prv[32],
	const uint8_t iskb[32], const uint8_t ikb[32],
	const uint8_t spkb[32], const uint8_t spkb_sig[64],
	const uint8_t opkb[32])
{
	struct packet_ratchet_astate_prerecv *rap = &state->rap;
	struct packet_ratchet_state_common *ra = &rap->rac;
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
packet_hshake_ahello(union packet_state *state, uint8_t *buf, size_t msgsize)
{
	struct hshake_ohello_msg *msg = (struct hshake_ohello_msg *)buf;
	struct packet_ratchet_astate_prerecv *rap = &state->rap;

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
	packet_lock(state, msg->message, msgsize);
}

static
size_t
send_ohello_message(union packet_state *state, union packet_state *p2pstate,
		uint8_t recipient_isk[32], uint8_t *buf, size_t bufsz,
		const uint8_t *content, size_t content_size)
{
	uint8_t *text = PACKET_TEXT(buf);
	uint8_t *ohellomsg = text + CHAT_FORWARD_MSG_BASE_SIZE + 2;
	size_t text_size = PACKET_TEXT_SIZE(bufsz);
	size_t innermsg_size = 2 + content_size;
	size_t ohellomsg_size = PACKET_P2PHELLO_SIZE(innermsg_size);
	size_t padded_ohellomsg_size = padme_enc(ohellomsg_size);
	size_t ohellomsg_padding = padded_ohellomsg_size - ohellomsg_size;
	size_t padded_innermsg_size = padded_ohellomsg_size - PACKET_P2PHELLO_SIZE(0);
	size_t ohellopacket_size = PACKET_BUF_SIZE(padded_ohellomsg_size);
	size_t innerpacket_size = PACKET_BUF_SIZE(padded_innermsg_size);
	size_t fwdmsg_size = CHAT_FORWARD_MSG_SIZE(2 + ohellopacket_size);
	size_t padded_fwdmsg_size = padme_enc(fwdmsg_size);
	size_t fwdmsg_padding = padded_fwdmsg_size - fwdmsg_size;

	if (persist_store8(PROTO_CHAT,             &text, &text_size)) goto fail;
	if (persist_store8(CHAT_FORWARD_MSG,       &text, &text_size)) goto fail;
	if (persist_store16_le(fwdmsg_size,        &text, &text_size)) goto fail;
	if (persist_storebytes(recipient_isk, 32,  &text, &text_size)) goto fail;
	if (persist_store8(1/*msg count*/,         &text, &text_size)) goto fail;
	if (persist_store16_le(ohellopacket_size,  &text, &text_size)) goto fail;
	if (persist_zeropad(40/*room for ohello*/, &text, &text_size)) goto fail;
	if (persist_store8(0/*ohello.msgtype*/,    &text, &text_size)) goto fail;
	if (persist_zeropad(96/*room for keys */,  &text, &text_size)) goto fail;
	if (persist_store16_le(innerpacket_size,   &text, &text_size)) goto fail;

	if (persist_zeropad(PACKET_HDR_SIZE,          &text, &text_size)) goto fail;
	if (persist_store16_le(content_size,          &text, &text_size)) goto fail;
	if (persist_storebytes(content, content_size, &text, &text_size)) goto fail;
	if (persist_zeropad(ohellomsg_padding,        &text, &text_size)) goto fail;
	packet_hshake_ahello(p2pstate, ohellomsg, padded_innermsg_size);

	if (persist_zeropad(fwdmsg_padding, &text, &text_size)) goto fail;
	packet_lock(state, buf, padded_fwdmsg_size);

	return padded_fwdmsg_size;
fail:
	return -1;
}

static
size_t
send_omsg_message(union packet_state *state, union packet_state *p2pstate,
		uint8_t recipient_isk[32], uint8_t *buf, size_t bufsz,
		const uint8_t *content, size_t content_size)
{
	uint8_t *text = PACKET_TEXT(buf);
	uint8_t *omsg = text + CHAT_FORWARD_MSG_BASE_SIZE + 2;
	size_t text_size = PACKET_TEXT_SIZE(bufsz);
	size_t innermsg_size = 2 + content_size;
	size_t padded_innermsg_size = padme_enc(innermsg_size);
	size_t innermsg_padding = padded_innermsg_size - innermsg_size;
	size_t innerpacket_size = PACKET_BUF_SIZE(padded_innermsg_size);
	size_t fwdmsg_size = CHAT_FORWARD_MSG_SIZE(2 + innerpacket_size);
	size_t padded_fwdmsg_size = padme_enc(fwdmsg_size);
	size_t fwdmsg_padding = padded_fwdmsg_size - fwdmsg_size;

	if (persist_store8(PROTO_CHAT,            &text, &text_size)) goto fail;
	if (persist_store8(CHAT_FORWARD_MSG,      &text, &text_size)) goto fail;
	if (persist_store16_le(fwdmsg_size,       &text, &text_size)) goto fail;
	if (persist_storebytes(recipient_isk, 32, &text, &text_size)) goto fail;
	if (persist_store8(1/*msg count*/,        &text, &text_size)) goto fail;
	if (persist_store16_le(innerpacket_size,  &text, &text_size)) goto fail;

	if (persist_zeropad(PACKET_HDR_SIZE,          &text, &text_size)) goto fail;
	if (persist_store16_le(content_size,          &text, &text_size)) goto fail;
	if (persist_storebytes(content, content_size, &text, &text_size)) goto fail;
	if (persist_zeropad(innermsg_padding,         &text, &text_size)) goto fail;
	packet_lock(p2pstate, omsg, padded_innermsg_size);

	if (persist_zeropad(fwdmsg_padding, &text, &text_size)) goto fail;
	packet_lock(state, buf, padded_fwdmsg_size);

	return padded_fwdmsg_size;
fail:
	return -1;
}

size_t
send_message(union packet_state *state, union packet_state *p2pstate,
		uint8_t recipient_isk[32], uint8_t *buf, size_t bufsz,
		const uint8_t *text, size_t text_size)
{
	return (p2pstate->ra.rac.prerecv ? send_ohello_message : send_omsg_message)
		(state, p2pstate, recipient_isk, buf, bufsz, text, text_size);
}
