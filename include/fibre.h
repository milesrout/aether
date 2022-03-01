extern void fibre_init(size_t stack_size);
extern void fibre_finish(void);
extern int fibre_yield(void);
extern void fibre_return(void);
extern int fibre_current(void);
extern void fibre_go(void (*)(void *), void *);
extern int fibre_wait_for_fd(int fd, int events);
extern int fibre_sleep(const struct timespec *);
extern int fibre_read(int fd, void *buf, size_t count);
