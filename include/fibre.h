extern void fibre_init(size_t stack_size);
extern void fibre_finish(void);
extern void fibre_return(void);
extern int fibre_yield(void);
extern int fibre_sleep(const struct timespec *);
extern void fibre_go(void (*)(void *), void *);
extern int fibre_current(void);
