extern int persist_read(uint8_t **buf, size_t *size, const char *filename, const uint8_t key[32]);
extern int persist_write(const char *filename, const uint8_t *buf, size_t size, const uint8_t key[32]);
