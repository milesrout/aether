extern void dumpbytes(const uint8_t *, size_t);
extern void displaykey(const char *, const uint8_t *, size_t);
extern void randbytes(uint8_t *, size_t);
extern void generate_hidden_keypair(uint8_t hidden_key[32], uint8_t private_key[32]);
extern void generate_kex_keypair(uint8_t public_key[32], uint8_t private_key[32]);
extern void generate_sig_keypair(uint8_t public_key[32], uint8_t private_key[32]);
/* BEGIN: these are derived from monocypher directly */
extern void store32_le(uint8_t out[4], uint32_t in);
extern uint32_t load32_le(const uint8_t s[4]);
extern void store64_le(uint8_t out[8], uint64_t in);
extern uint64_t load64_le(const uint8_t s[8]);
/* END: these are derived from monocypher directly */
extern void sign_key(uint8_t sig[64],
	const uint8_t isk_prv[32], const uint8_t isk[32],
	const char name[4], const uint8_t key[32]);
extern int check_key(const uint8_t isk[32], const char name[4],
	const uint8_t key[32], const uint8_t sig[64]);
