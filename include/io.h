extern struct sockaddr *sstosa(struct sockaddr_storage *ss);
extern size_t safe_read(int fd, uint8_t *buf, size_t max_size_p1);
extern size_t safe_read_nonblock(int fd, uint8_t *buf, size_t max_size_p1);
extern size_t safe_recvfrom(int fd, uint8_t *buf, size_t max_size_p1,
	struct sockaddr_storage *peeraddr, socklen_t *peeraddr_len);
extern void safe_write(int fd, const uint8_t *buf, size_t size);
extern void safe_sendto(int fd, const uint8_t *buf, size_t size,
	struct sockaddr *peeraddr, socklen_t peeraddr_len);
extern int setclientup(const char *addr, const char *port);
