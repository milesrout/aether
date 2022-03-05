enum fibre_prio {
	/* a fibre used for ui or other interactive functionality */
	FP_HIGH,
	/* any other fibre */
	FP_NORMAL,
	/* lower priority fibres that should still take priority over background tasks */
	FP_LOW,
	/* a fibre used for non-latency-sensitive background tasks */
	FP_BACKGROUND,
	/* number of priorities */
	FP_NUM_PRIOS
};
extern void fibre_init(size_t stack_size);
extern void fibre_finish(void);
extern int fibre_yield(void);
extern void fibre_return(void);
extern int fibre_current(void);
extern void fibre_go(int prio, void (*)(int, void *), int, void *);
extern int fibre_awaitfd(int fd, int events);
extern void fibre_close(int fd);
extern int fibre_sleep(const struct timespec *);
extern ssize_t fibre_read(int, void *, size_t);
extern ssize_t fibre_write(int, const void *, size_t);
extern ssize_t fibre_send(int, const void *, size_t, int flags);
extern ssize_t fibre_recv(int, void *, size_t, int flags);
extern ssize_t fibre_recvfrom(int, void *, size_t, int flags,
	struct sockaddr *, socklen_t *);
extern ssize_t fibre_sendto(int, const void *, size_t, int flags,
	struct sockaddr *, socklen_t);
extern int fibre_sleep_s(time_t seconds);
extern int fibre_sleep_ms(long milliseconds);
extern int fibre_sleep_us(long microseconds);
extern int fibre_sleep_ns(long nanoseconds);
