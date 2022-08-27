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
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "err.h"
#include "util.h"
#include "fibre.h"
#include "queue.h"

#ifdef BUILD_VALGRIND
#include <valgrind/valgrind.h>
#endif

#include "fibre_switch.h"

#ifdef BUILD_SANITISE
void __sanitizer_start_switch_fiber(void **, const void *, size_t);
void __sanitizer_finish_switch_fiber(void *, const void **, size_t *);
#endif

static void *mmap_allocate(size_t m);
static void mmap_deallocate(void *p, size_t n);

struct fibre_store_list;
static
void
fibre_store_list_enqueue(struct fibre_store_list *list, int fibre);

static struct {
	long int fstat_stack_allocs;
	long int fstat_fibre_go_calls;
	long int fstat_iocalls;
} fibre_stats = {0};

/*
 * This structure represents an execution context, namely it contains the
 * values for all callee-saved registers, and the stack pointer. Because we
 * switch fibres using a function call, the compiler takes care of saving
 * everything else.
 */
struct fibre_ctx {
	uint64_t fc_rsp;
	uint64_t fc_r15;
	uint64_t fc_r14;
	uint64_t fc_r13;
	uint64_t fc_r12;
	uint64_t fc_rbx;
	uint64_t fc_rbp;
};

enum fibre_state {
	/* a fibre that represents a possibly-uninitialised execution context */
	FS_EMPTY,
	/* the fibre that represents the current execution context */
	FS_ACTIVE,
	/* a fibre that is waiting for an I/O operation to be completed */
	FS_WAITING,
	/* a fibre that represents a valid, suspended execution context */
	FS_READY
};

enum fibre_list {
	FL_HIGH,
	FL_NORMAL,
	FL_LOW,
	FL_BACKGROUND,
	FL_HIGH_WAITING,
	FL_NORMAL_WAITING,
	FL_LOW_WAITING,
	FL_BACKGROUND_WAITING,
	FL_EMPTY,
	FL_NUM_LISTS
};

/*
 * This structure represents a fibre. It includes the execution context (struct
 * fibre_ctx) along with the state of the fibre and a pointer to the fibre's
 * stack. This is everything you need to know whether a fibre can be switched
 * to and how to switch to it.
 */
struct fibre {
	struct   fibre_ctx f_ctx;
	short    f_state;
	short    f_prio;
	int      f_flags;
	unsigned f_valgrind_id;
	int      f_id;
	int      f_fd;
	int      f_fdcount;
	int     *f_fds;
	char    *f_stack;
	void   (*f_func)(long, void *);
	void    *f_datap;
	long     f_datan;
};

/*
 * This is a node in an intrusive bidirectional linked list of struct fibres.
 */
struct fibre_store_node {
	TAILQ_ENTRY(fibre_store_node) fsn_nodes;
	struct fibre fsn_fibre;
};

static struct fibre_store_node fibres[4096];
static TAILQ_HEAD(global_empty_nodes, fibre_store_node) global_empty_nodes;
static int next_invalid_fibre;

static
void
fibre_setup(int fibre)
{
	fibres[fibre].fsn_fibre.f_state = FS_EMPTY;
	fibres[fibre].fsn_fibre.f_flags = 0;
	fibres[fibre].fsn_fibre.f_fdcount = 0;
	fibres[fibre].fsn_fibre.f_fds = NULL;
	fibres[fibre].fsn_fibre.f_fd = -1;
	fibres[fibre].fsn_fibre.f_stack = NULL;
}

/*
 * This is the control block for a linked list of struct fibres.
 */
struct fibre_store_list {
	TAILQ_HEAD(fsl_nodes, fibre_store_node) fsl_nodes;
	int fsl_count;
	int fsl_epfd;
};

static
void
fibre_store_list_init(struct fibre_store_list *list)
{
	TAILQ_INIT(&list->fsl_nodes);
	list->fsl_count = 0;
	list->fsl_epfd = -1;
}

/* adds a fibre to the start of the list */
/*
static
void
fibre_store_list_enqueue(struct fibre_store_list *list, int fibre)
{
	int L = list - global_fibre_store.fs_lists;
	fprintf(stderr, "fibre_store_list_enqueue(list=%p, fibre=%d)\n",
		(void*)list, fibre);

	struct fibre_store_node *node = fibres + fibre;
	TAILQ_INSERT_HEAD(&list->fsl_nodes, node, fsn_nodes);
	list->fsl_count++;
}
*/

/*
 * there is a list of ready fibres for each priority level plus a list of
 * empty fibres.
 */
struct fibre_store {
	size_t fs_stack_size;
	struct fibre_store_list fs_lists[FL_NUM_LISTS];
	int fs_epfd;
};

static
struct fibre_store
global_fibre_store;

/* Removes a fibre from the end of the list */
static
int
try_fibre_store_list_dequeue_ready(int prio)
{
	struct fibre_store_list *list = &global_fibre_store.fs_lists[prio];
	struct fibre_store_node *node;

	/* fprintf(stderr, "try_fibre_store_list_dequeue_ready(prio=%d)\n", prio); */

	if (TAILQ_EMPTY(&list->fsl_nodes))
		return -1;

	node = TAILQ_LAST(&list->fsl_nodes, fsl_nodes);
	/* fprintf(stderr, "dequeued fibre %ld\n", node - fibres); */
	TAILQ_REMOVE(&list->fsl_nodes, node, fsn_nodes);
	list->fsl_count--;
	return node - fibres;
}

/*
 * This takes fibres from the start of the list instead of the end, treating the
 * empties list as a stack.  The other lists are treated as queues.
 */
static
int
fibre_store_get_first_empty(void)
{
	struct fibre_store_node *node;

	if (TAILQ_EMPTY(&global_empty_nodes)) {
		int fibre = ++next_invalid_fibre;
		fibre_setup(fibre);
		return fibre;
	}

	node = TAILQ_FIRST(&global_empty_nodes);
	TAILQ_REMOVE(&global_empty_nodes, node, fsn_nodes);
	return node - fibres;
}

/*
 * This transfers a node from the waiting list to the ready list
 */
static
void
transfer_node(struct fibre_store_node *node,
		struct fibre_store_list *ready,
		struct fibre_store_list *waiting)
{
	/* fprintf(stderr, "transfer_node()\n"); */

	TAILQ_REMOVE(&waiting->fsl_nodes, node, fsn_nodes);
	TAILQ_INSERT_TAIL(&ready->fsl_nodes, node, fsn_nodes);
	waiting->fsl_count--;
	ready->fsl_count++;
	node->fsn_fibre.f_state = FS_READY;
}

static
int
fibre_store_poll(int prio)
{
	struct fibre_store_list *waiting
		= &global_fibre_store.fs_lists[FL_HIGH_WAITING + prio];
	struct fibre_store_list *ready = &global_fibre_store.fs_lists[prio];
	struct epoll_event ev[8] = {0};
	const char *opterrstring;
	int sockerr, opterr;
	struct fibre *f;
	ptrdiff_t i;
	int count;

	/* fprintf(stderr, "fibre_store_poll(prio=%d)\n", prio); */

	do count = epoll_wait(waiting->fsl_epfd, ev, 8, 0);
	while (count == -1 && errno == EINTR);
	if (count == -1)
		err(1, "epoll_wait");

	for (i = 0; i < count; i++) {
		/* f = &((struct fibre_store_node *)ev[i].data.ptr)->fsn_fibre; */
		f = &fibres[ev[i].data.u32].fsn_fibre;

		if (ev[i].events & EPOLLERR) {
			socklen_t len = sizeof sockerr;
			if (getsockopt(f->f_fd, SOL_SOCKET, SO_ERROR, &sockerr,
					&len)) {
				opterr = errno;
				opterrstring = strerror(opterr);
				fprintf(stderr, "getsockopt(%d, ...) -> %s\n",
					f->f_fd, opterrstring);
			}
			errno = sockerr;
			err(1, "epoll_wait -> EPOLLERR");
		}

		transfer_node(&fibres[ev[i].data.u32], ready, waiting);
		ev[i].events = 0;
		if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_MOD,
				f->f_fd, &ev[i]))
			err(1, "epoll_ctl(EPOLL_CTL_MOD)");
	}

	return 0;
}

static
int
try_fibre_store_poll_dequeue(int prio)
{
	struct fibre_store_list *waiting
		= &global_fibre_store.fs_lists[FL_HIGH_WAITING + prio];

	/* fprintf(stderr, "try_fibre_store_poll_dequeue(prio=%d)\n", prio); */

	if (waiting->fsl_count)
		fibre_store_poll(prio);
	return try_fibre_store_list_dequeue_ready(prio);
}

static
int
current_fibre;

static
const int
main_fibre = 0;

static
int
global_fibre_count;

static
void
print_fibre_lists(void)
{
	ptrdiff_t i;

	for (i = 0; i < FL_NUM_LISTS; i++) {
		struct fibre_store_list *list = &global_fibre_store.fs_lists[i];
		struct fibre_store_node *node;
		if (TAILQ_EMPTY(&list->fsl_nodes)) {
			fprintf(stderr, "%ld: (empty)\n", i);
			continue;
		}
		fprintf(stderr, "%ld: ", i);
		TAILQ_FOREACH(node, &list->fsl_nodes, fsn_nodes) {
			fprintf(stderr, "%ld ", node - fibres);
		}
		fprintf(stderr, "\n");
	}
}

static
int
fibre_store_get_next_ready(void)
{
	ptrdiff_t prio;
	int ecount, idx = -1;
	struct epoll_event ev = {0};

	while (idx == -1) {
		for (prio = 0; prio < FP_NUM_PRIOS; prio++) {
			idx = try_fibre_store_poll_dequeue(prio);
			if (idx != -1) {
				/* fprintf(stderr, "inloop = %d\n", idx); */
				return idx;
			}
		}

		do ecount = epoll_wait(global_fibre_store.fs_epfd, &ev, 1, -1);
		while (ecount == -1 && errno == EINTR);
		assert(ecount == 1);

		assert(ev.events & EPOLLIN);
		assert(!(ev.events & EPOLLERR));

		prio = ev.data.u32;
		idx = try_fibre_store_poll_dequeue(prio);
	}

	/* fprintf(stderr, "afterloop = %d\n", idx); */
	return idx;
}

int
fibre_current(void)
{
	return current_fibre;
}

void
fibre_init(size_t stack_size)
{
	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
	ptrdiff_t i;
	int epfd;
	struct epoll_event ev = {0};

	global_fibre_store.fs_stack_size = stack_size;
	global_fibre_store.fs_epfd = epoll_create1(O_CLOEXEC);

	for (i = 0; i < FL_NUM_LISTS; i++)
		fibre_store_list_init(&global_fibre_store.fs_lists[i]);

	for (i = 0; i < FP_NUM_PRIOS; i++) {
		epfd = epoll_create1(O_CLOEXEC);
		if (epfd == -1)
			err(1, "epoll_create1");

		ev.events = EPOLLIN;
		ev.data.u32 = i;

		global_fibre_store.fs_lists[FL_HIGH_WAITING + i].fsl_epfd = epfd;

		if (epoll_ctl(global_fibre_store.fs_epfd, EPOLL_CTL_ADD, epfd, &ev))
			err(1, "epoll_ctl(EPOLL_CTL_ADD)");
	}

	/* main_fibre = fibre_store_get_first_empty(); */
	fibres[main_fibre].fsn_fibre.f_state = FS_ACTIVE;
	fibres[main_fibre].fsn_fibre.f_fd = -1;
	fibres[main_fibre].fsn_fibre.f_id = 0;
	fibres[main_fibre].fsn_fibre.f_prio = FP_NORMAL; /* is this right? */
	fibres[main_fibre].fsn_fibre.f_stack = NULL;

	current_fibre = main_fibre;
}

void
fibre_finish(void)
{
	warnx("Deinitialising fibre system");

	warnx("Fibre stat stack_allocs: %ld", fibre_stats.fstat_stack_allocs);
	warnx("Fibre stat fibre_go_calls: %ld", fibre_stats.fstat_fibre_go_calls);
	warnx("Fibre stat iocalls: %ld", fibre_stats.fstat_iocalls);
}

void
fibre_return(void)
{
	/* fprintf(stderr, "fibre_return(current=%d)\n", current_fibre); */

	if (current_fibre != main_fibre) {
		fibres[current_fibre].fsn_fibre.f_state = FS_EMPTY;
		fibre_store_list_enqueue(
			&global_fibre_store.fs_lists[FL_EMPTY],
			current_fibre);
		/* TODO: When we finish with a fibre, we should mark its stack
		 * as no longer needed.  For now we will deallocate it, but
		 * constantly allocating and deallocating stacks might be
		 * wasteful.  It it does turn out to be, then we should reuse
		 * stacks.  However, reusing stacks has the potential for
		 * information leakage.  MADV_DONTNEED should zero-fill the
		 * pages if they're ever reused, however.  We need an
		 * allocator-dependent equivalent of:
		 *
		 * madvise(current_fibre->stack, MADV_DONTNEED);
		 *
		 * Or we need to hardcode the use of the mmap allocator for
		 * allocating stacks.
		 */
#ifdef BUILD_VALGRIND
		VALGRIND_STACK_DEREGISTER(current_fibre->f_valgrind_id);
#endif
		fibre_yield();
		/* unreachable */
	}
	while (fibre_yield())
		;
	fibre_finish();
}

static
void
fibre_enqueue_ready(int f)
{
	/* fprintf(stderr, "fibre_enqueue_ready(f=%d, prio=%d, state=%d);\n", */
		/* f, fibres[f].fsn_fibre.f_prio, fibres[f].fsn_fibre.f_state); */
	fibres[f].fsn_fibre.f_state = FS_READY;
	fibre_store_list_enqueue(
		&global_fibre_store.fs_lists[fibres[f].fsn_fibre.f_prio],
		f);
}

static
void
fibre_enqueue_waiting(int f, int count, int *fd, int *events)
{
	int prio = fibres[f].fsn_fibre.f_prio;
	struct fibre_store_list *waiting =
		&global_fibre_store.fs_lists[FL_HIGH_WAITING + prio];
	struct epoll_event ev = {0};

	/* fprintf(stderr, "fibre_enqueue_waiting(%d(prio=%d), %d);\n", */
	/* 	f, prio, count); */

	while (count--) {
		ev.events = events[count];
		ev.data.u32 = f;

		if (fibres[f].fsn_fibre.f_fd == fd[count]) {
			if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_MOD,
					fibres[f].fsn_fibre.f_fd, &ev))
				err(1, "epoll_ctl(EPOLL_CTL_MOD)");
		} else {
			if (fibres[f].fsn_fibre.f_fd != -1) {
				if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_DEL,
						fibres[f].fsn_fibre.f_fd,
						NULL))
					err(1, "epoll_ctl(EPOLL_CTL_DEL)");
			}
			fibres[f].fsn_fibre.f_fd = fd[count];
			if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_ADD,
					fibres[f].fsn_fibre.f_fd, &ev))
				err(1, "epoll_ctl(EPOLL_CTL_ADD)");
		}
	}

	fibres[f].fsn_fibre.f_state = FS_WAITING;
	fibre_store_list_enqueue(waiting, f);
}

ssize_t
fibre_read(int fd, void *buf, size_t count)
{
	ssize_t n;

	fibre_stats.fstat_iocalls++;
	n = read(fd, buf, count);
	while (n == -1 && errno == EAGAIN) {
		fibre_awaitfd(fd, EPOLLIN);
		n = read(fd, buf, count);
	}

	return n;
}

ssize_t
fibre_recv(int fd, void *buf, size_t count, int flags)
{
	ssize_t n;

	fibre_stats.fstat_iocalls++;
	n = recv(fd, buf, count, flags|MSG_DONTWAIT);
	while (n == -1 && errno == EAGAIN) {
		fibre_awaitfd(fd, EPOLLIN);
		n = recv(fd, buf, count, flags|MSG_DONTWAIT);
	}

	return n;
}

ssize_t
fibre_write(int fd, const void *buf, size_t count)
{
	ssize_t n;

	fibre_stats.fstat_iocalls++;
	n = write(fd, buf, count);
	while (n == -1 && errno == EAGAIN) {
		fibre_awaitfd(fd, EPOLLOUT);
		n = write(fd, buf, count);
	}

	return n;
}

ssize_t
fibre_send(int fd, const void *buf, size_t count, int flags)
{
	ssize_t n;

	fibre_stats.fstat_iocalls++;
	n = send(fd, buf, count, flags|MSG_DONTWAIT);
	while (n == -1 && errno == EAGAIN) {
		fibre_awaitfd(fd, EPOLLOUT);
		n = send(fd, buf, count, flags|MSG_DONTWAIT);
	}

	return n;
}

ssize_t
fibre_recvfrom(int fd, void *buf, size_t len, int flags,
		struct sockaddr *peeraddr, socklen_t *peeraddr_len)
{
	ssize_t n;

	fibre_stats.fstat_iocalls++;
	n = recvfrom(fd, buf, len, MSG_DONTWAIT|flags,
		peeraddr, peeraddr_len);
	while (n == -1 && errno == EAGAIN) {
		fibre_awaitfd(fd, EPOLLOUT);
		n = recvfrom(fd, buf, len, MSG_DONTWAIT|flags,
			peeraddr, peeraddr_len);
	}

	return n;
}

ssize_t
fibre_sendto(int fd, const void *buf, size_t len, int flags,
		struct sockaddr *peeraddr, socklen_t peeraddr_len)
{
	ssize_t n;

	fibre_stats.fstat_iocalls++;
	n = sendto(fd, buf, len, MSG_DONTWAIT|flags,
		peeraddr, peeraddr_len);
	while (n == -1 && errno == EAGAIN) {
		fibre_awaitfd(fd, EPOLLOUT);
		n = sendto(fd, buf, len, MSG_DONTWAIT|flags,
			peeraddr, peeraddr_len);
	}

	return n;
}

/*
 * awaitfd = fibre_yield_impl(1, &fd, &events)
 * awaitfd_timeout = fibre_yield_impl(2, &[fd, timerfd], &[events, POLLIN]);
 * yield = fibre_yield_impl(0, NULL, NULL)
 */
static
int
fibre_yield_impl(int count, int *fd, int *events)
{
	struct fibre_ctx *old, *new;
	int old_fibre, fibre;

	/* print_fibre_lists(); */

	/* fprintf(stderr, "fibre_yield_impl: Yielding from fibre %d.\n", current_fibre); */

	if (fibres[current_fibre].fsn_fibre.f_state != FS_EMPTY) {
		if (count > 0)
			fibre_enqueue_waiting(current_fibre, count, fd, events);
	}

	fibre = fibre_store_get_next_ready();
	if (fibre == -1) {
		/* fprintf(stderr, "Yielding from fibre %d, finishing\n", current_fibre); */
		return 0;
	}

	if (fibres[current_fibre].fsn_fibre.f_state != FS_EMPTY) {
		if (count == 0)
			fibre_enqueue_ready(current_fibre);
	}

	fibres[fibre].fsn_fibre.f_state = FS_ACTIVE;
	old = &fibres[current_fibre].fsn_fibre.f_ctx;
	new = &fibres[fibre].fsn_fibre.f_ctx;
	old_fibre = current_fibre;
	current_fibre = fibre;
	(void)old_fibre;
	/* fprintf(stderr, "Paused fibre %d.\n", old_fibre); */
#ifdef BUILD_SANITISE
	__sanitizer_start_switch_fiber(NULL,
		fibres[current_fibre].fsn_fibre.f_stack,
		global_fibre_store.fs_stack_size);
#endif
	fibre_switch(old, new);
#ifdef BUILD_SANITISE
	__sanitizer_finish_switch_fiber(NULL, NULL, NULL);
#endif
	/* fprintf(stderr, "Resumed fibre %d.\n", current_fibre); */
	return 1;
}

int
fibre_awaitfd(int fd, int events)
{
	/* fprintf(stderr, "fibre_awaitfd(current=%d, fd=%d)\n", current_fibre, fd); */
	return fibre_yield_impl(1, &fd, &events);
}

void
fibre_close(int fd)
{
	int i;

	for (i = 0; i < FP_NUM_PRIOS; i++)
		if (epoll_ctl(global_fibre_store.fs_lists[FL_HIGH_WAITING + i].fsl_epfd,
				EPOLL_CTL_DEL, fd, NULL) && errno != ENOENT)
			warn("epoll_ctl(EPOLL_CTL_DEL)");

	if (close(fd))
		warn("close");

	if (fibres[current_fibre].fsn_fibre.f_fd == fd)
		fibres[current_fibre].fsn_fibre.f_fd = -1;
}

int
fibre_yield(void)
{
	/* fprintf(stderr, "fibre_yield(current=%d)\n", current_fibre); */
	return fibre_yield_impl(0, NULL, NULL);
}

#define FMTREG "0x%010llx"

static void
fibre_stop(void)
{
	fibre_return();
}

static
void
fibre_call(void)
{
#ifdef BUILD_SANITISE
	__sanitizer_finish_switch_fiber(NULL, NULL, NULL);
#endif
	/* fprintf(stderr, "Started fibre %d.\n", current_fibre); */
	fibres[current_fibre].fsn_fibre.f_func(
		fibres[current_fibre].fsn_fibre.f_datan,
		fibres[current_fibre].fsn_fibre.f_datap);
}

void
fibre_go(int prio, void (*func)(long, void *), long datan, void *datap)
{
	char *stack;
	size_t size = global_fibre_store.fs_stack_size;
	struct fibre *fibre;
	int f;

	f = fibre_store_get_first_empty();
	fibre = &fibres[f].fsn_fibre;

	fibre_stats.fstat_fibre_go_calls++;
	if (fibre->f_stack == NULL) {
		fibre_stats.fstat_stack_allocs++;
		stack = mmap_allocate(size);
	} else {
		stack = fibre->f_stack;
	}
#ifdef BUILD_VALGRIND
	fibre->f_valgrind_id = VALGRIND_STACK_REGISTER(stack, stack + size);
#endif

	*(uint64_t *)&stack[size -  8] = (uint64_t)fibre_stop;
	*(uint64_t *)&stack[size - 16] = (uint64_t)fibre_call;
	fibre->f_ctx.fc_rsp = (uint64_t)&stack[size - 16];

	fibre->f_id = ++global_fibre_count;
	fibre->f_state = FS_READY;
	fibre->f_prio = prio;
	fibre->f_stack = stack;
	fibre->f_func = func;
	fibre->f_datap = datap;
	fibre->f_datan = datan;
	fibre_enqueue_ready(f);
}

static
void *
mmap_allocate(size_t m)
{
	void *p;

	p = mmap(NULL, m, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		/* MAP_GROWSDOWN|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); */
	if (p == MAP_FAILED)
		err(1, "Failed to allocate (mmap)");
#ifdef BUILD_VALGRIND
	VALGRIND_MALLOCLIKE_BLOCK(p, m, 0, 1);
#endif
	return p;
}

static
void
mmap_deallocate(void *p, size_t n)
{
	int r;

	r = munmap(p, n);
	if (r == -1)
		err(1, "Failed to deallocate (munmap)");
#ifdef BUILD_VALGRIND
	VALGRIND_FREELIKE_BLOCK(p, 0);
#endif
}

/* adds a fibre to the start of the list */
static
void
fibre_store_list_enqueue(struct fibre_store_list *list, int fibre)
{
	int L = list - global_fibre_store.fs_lists;
	/* fprintf(stderr, "fibre_store_list_enqueue(list=%d, fibre=%d)\n", */
	/* 	L, fibre); */

	struct fibre_store_node *node = fibres + fibre;
	/* print_fibre_lists(); */
	TAILQ_INSERT_HEAD(&list->fsl_nodes, node, fsn_nodes);
	/* fprintf(stderr, "Failure?\n"); */
	/* print_fibre_lists(); */
	list->fsl_count++;
}
