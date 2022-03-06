extern int persist_read(uint8_t **buf, size_t *size, const char *filename, const char *password, size_t password_size);
extern int persist_write(const char *filename, const uint8_t *buf, size_t size, const char *password, size_t password_size);
