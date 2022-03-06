extern int persist_read(uint8_t **pbuf, size_t *psize, const char *filename, const char *password, size_t password_size);
extern int persist_write(const char *filename, const uint8_t *buf, size_t size, const char *password, size_t password_size);
extern int persist_loadbytes(uint8_t *buf, size_t size, const uint8_t **pbuf, size_t *psize);
extern int persist_load32_le(uint32_t *n, const uint8_t **pbuf, size_t *psize);
extern int persist_storebytes(const uint8_t *buf, size_t size, uint8_t **pbuf, size_t *psize);
extern int persist_store32_le(const uint32_t *n, uint8_t **pbuf, size_t *psize);
