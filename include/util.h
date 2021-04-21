extern void randbytes(uint8_t *data, size_t size);
extern void generate_kex_keypair(uint8_t public_key[32], uint8_t private_key[32]);
extern void generate_sign_keypair(uint8_t public_key[32], uint8_t private_key[32]);
/* BEGIN: these are derived from monocypher directly */
extern void store32_le(uint8_t out[4], uint32_t in);
extern uint32_t load32_le(const uint8_t s[4]);
/* END: these are derived from monocypher directly */
extern void sign_key(uint8_t sig[64],
	const uint8_t isk_prv[32], const uint8_t isk[32],
	const char name[4], const uint8_t key[32]);
extern int check_key(const uint8_t isk[32], const char name[4],
	const uint8_t key[32], const uint8_t sig[64]);
