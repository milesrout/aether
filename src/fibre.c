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

static void *mmap_allocate(size_t m);
static void  mmap_deallocate(void *p, size_t n);

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
	struct fibre_ctx f_ctx;
	short f_state;
	short f_prio;
	int f_flags;
	unsigned f_valgrind_id;
	int f_id;
	int f_fd;
	int f_datan;
	char *f_stack;
	void (*f_func)(int, void *);
	void *f_datap;
};

static
void
fibre_setup(struct fibre *fibre)
{
	fibre->f_state = FS_EMPTY;
	fibre->f_flags = 0;
	fibre->f_fd = -1;
	fibre->f_stack = NULL;
}

/*
 * This is a node in an intrusive bidirectional linked list of struct fibres.
 */
struct fibre_store_node {
	TAILQ_ENTRY(fibre_store_node) fsn_nodes;
	struct fibre fsn_fibre;
};

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
static
void
fibre_store_list_enqueue(struct fibre_store_list *list, struct fibre *fibre)
{
	struct fibre_store_node *node =
		container_of(struct fibre_store_node, fsn_fibre, fibre);

	TAILQ_INSERT_HEAD(&list->fsl_nodes, node, fsn_nodes);
	list->fsl_count++;
}

/* removes a fibre from the end of the list */
static
struct fibre *
try_fibre_store_list_dequeue(struct fibre_store_list *list)
{
	struct fibre_store_node *node;

	if (TAILQ_EMPTY(&list->fsl_nodes))
		return NULL;

	node = TAILQ_LAST(&list->fsl_nodes, fsl_nodes);
	TAILQ_REMOVE(&list->fsl_nodes, node, fsn_nodes);
	list->fsl_count--;
	return &node->fsn_fibre;
}

/*
 * This value is calculated so that each fibre_store_block should be 4xpage-sized.
 * e.g. if sizeof(fibre_store_node) is 160 bytes, this value should be 25.
 */
#define FIBRE_STORE_NODES_PER_BLOCK 136

/*
 * struct fibres are allocated in page-sized blocks, which at the moment are
 * never deallocated, but the struct fibres within them can be reused.
 */
struct fibre_store_block {
	SLIST_ENTRY(fibre_store_block) fsb_blocks;
	struct fibre_store_node fsb_nodes[FIBRE_STORE_NODES_PER_BLOCK];
};

/*
 * there is a list of ready fibres for each priority level plus a list of
 * empty fibres.
 */
struct fibre_store {
	size_t fs_stack_size;
	SLIST_HEAD(fs_blocks, fibre_store_block) fs_blocks;
	/* struct fibre_store_block *fs_blocks; */
	/* the last list is for FS_EMPTY fibres */
	struct fibre_store_list fs_lists[FL_NUM_LISTS];
	int fs_epfd;
};

static
void
fibre_store_block_create(struct fibre_store_list *list, struct fibre_store *store)
{
	struct fibre_store_block *block =
		mmap_allocate(sizeof *block);
	ptrdiff_t i;

	for (i = 0; i < FIBRE_STORE_NODES_PER_BLOCK; i++) {
		TAILQ_INSERT_TAIL(&list->fsl_nodes, block->fsb_nodes + i, fsn_nodes);
		fibre_setup(&block->fsb_nodes[i].fsn_fibre);
	}

	SLIST_INSERT_HEAD(&store->fs_blocks, block, fsb_blocks);
}

/*
 * This takes fibres from the start of the list instead of the end, treating the
 * empties list as a stack. The other lists are treated as queues.
 */
static
struct fibre *
fibre_store_get_first_empty(struct fibre_store *store)
{
	struct fibre_store_list *empties_list = &store->fs_lists[FL_EMPTY];
	struct fibre_store_node *node;

	if (TAILQ_EMPTY(&empties_list->fsl_nodes)) {
		fibre_store_block_create(empties_list, store);
	}

	node = TAILQ_FIRST(&empties_list->fsl_nodes);
	TAILQ_REMOVE(&empties_list->fsl_nodes, node, fsn_nodes);
	return &node->fsn_fibre;
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
	TAILQ_REMOVE(&waiting->fsl_nodes, node, fsn_nodes);
	TAILQ_INSERT_TAIL(&ready->fsl_nodes, node, fsn_nodes);
	waiting->fsl_count--;
	ready->fsl_count++;
	node->fsn_fibre.f_state = FS_READY;
}

static
int
fibre_store_poll(struct fibre_store_list *ready,
		struct fibre_store_list *waiting)
{
	struct epoll_event ev[8];
	const char *opterrstring;
	int sockerr, opterr;
	struct fibre *f;
	ptrdiff_t i;
	int count;

	do count = epoll_wait(waiting->fsl_epfd, ev, 8, 0);
	while (count == -1 && errno == EINTR);
	if (count == -1)
		err(EXIT_FAILURE, "epoll_wait");

	for (i = 0; i < count; i++) {
		f = &((struct fibre_store_node *)ev[i].data.ptr)->fsn_fibre;

		if (ev[i].events & EPOLLERR) {
			socklen_t len = sizeof sockerr;
			if (getsockopt(f->f_fd, SOL_SOCKET, SO_ERROR, &sockerr, &len)) {
				opterr = errno;
				opterrstring = strerror(opterr);
				fprintf(stderr, "getsockopt(%d, SOL_SOCKET, SO_ERROR) -> %s\n",
					f->f_fd, opterrstring);
			}
			errno = sockerr;
			err(EXIT_FAILURE, "epoll_wait -> EPOLLERR");
		}

		transfer_node(ev[i].data.ptr, ready, waiting);
		ev[i].events = 0;
		if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_MOD, f->f_fd, &ev[i]))
			err(EXIT_FAILURE, "epoll_ctl(EPOLL_CTL_MOD)");
	}

	return 0;
}

static
struct fibre *
try_fibre_store_poll_dequeue(
		struct fibre_store_list *ready,
		struct fibre_store_list *waiting)
{
	if (waiting->fsl_count)
		fibre_store_poll(ready, waiting);
	return try_fibre_store_list_dequeue(ready);
}

static
struct fibre *
fibre_store_get_next_ready(struct fibre_store *store)
{
	struct fibre *f = NULL;
	ptrdiff_t i;
	int ecount;
	struct epoll_event ev;

	while (f == NULL) {
		for (i = 0; i < FP_NUM_PRIOS; i++) {
			f = try_fibre_store_poll_dequeue(&store->fs_lists[i],
				&store->fs_lists[FL_HIGH_WAITING + i]);
			if (f) return f;
		}

		do ecount = epoll_wait(store->fs_epfd, &ev, 1, -1);
		while (ecount == -1 && errno == EINTR);
		assert(ecount == 1);

		assert(ev.events & EPOLLIN);
		assert(!(ev.events & EPOLLERR));

		i = ev.data.u32;
		f = try_fibre_store_poll_dequeue(&store->fs_lists[i],
			&store->fs_lists[FL_HIGH_WAITING + i]);
	}

	return f;
}

static
struct fibre
*current_fibre, *main_fibre;

static
struct fibre_store
global_fibre_store;

static
int
global_fibre_count;

int
fibre_current(void)
{
	return current_fibre->f_id;
}

void
fibre_init(size_t stack_size)
{
	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
	ptrdiff_t i;
	int epfd;
	struct epoll_event ev;

	warnx("Initialising fibre system with %luKiB-sized stacks",
		stack_size / 1024);

#define BLOCK_SIZE (sizeof(struct fibre_store_block))
#define NODE_SIZE (sizeof(struct fibre_store_node))
	if (BLOCK_SIZE > 4 * page_size)
		warnx("fibre_store_block is too big to fit in four pages: lower FIBRE_STORE_NODES_PER_BLOCK (%lu)",
			BLOCK_SIZE);
	else if (BLOCK_SIZE + NODE_SIZE <= 4 * page_size)
		warnx("fibre_store_block could be bigger: raise FIBRE_STORE_NODES_PER_BLOCK (%lu)",
			BLOCK_SIZE);
	else
		warnx("fibre_store_block fits perfectly in four pages (%lu)",
			BLOCK_SIZE);
#undef BLOCK_SIZE
#undef NODE_SIZE

	global_fibre_store.fs_stack_size = stack_size;
	SLIST_INIT(&global_fibre_store.fs_blocks);
	global_fibre_store.fs_epfd = epoll_create1(O_CLOEXEC);

	for (i = 0; i < FL_NUM_LISTS; i++)
		fibre_store_list_init(&global_fibre_store.fs_lists[i]);

	for (i = 0; i < FP_NUM_PRIOS; i++) {
		epfd = epoll_create1(O_CLOEXEC);
		if (epfd == -1)
			err(EXIT_FAILURE, "epoll_create1");

		ev.events = EPOLLIN;
		ev.data.u32 = i;

		global_fibre_store.fs_lists[FL_HIGH_WAITING + i].fsl_epfd = epfd;

		if (epoll_ctl(global_fibre_store.fs_epfd, EPOLL_CTL_ADD, epfd, &ev))
			err(EXIT_FAILURE, "epoll_ctl(EPOLL_CTL_ADD)");
	}

	main_fibre = fibre_store_get_first_empty(&global_fibre_store);
	main_fibre->f_state = FS_ACTIVE;
	main_fibre->f_fd = -1;
	main_fibre->f_id = 0;
	main_fibre->f_prio = FP_NORMAL; /* is this right? */
	main_fibre->f_stack = NULL;

	current_fibre = main_fibre;
}

/* This should be further up, but the assertion requires it to be after the
 * declaration of main_fibre */
static
void
fibre_store_destroy(struct fibre_store *store)
{
	ptrdiff_t i;
	struct fibre_store_block *block;

	while (!SLIST_EMPTY(&store->fs_blocks)) {
		block = SLIST_FIRST(&store->fs_blocks);

		for (i = 0; i < FIBRE_STORE_NODES_PER_BLOCK; i++) {
			if (&block->fsb_nodes[i].fsn_fibre == main_fibre)
				continue;
			if (block->fsb_nodes[i].fsn_fibre.f_stack == NULL)
				continue;
			mmap_deallocate(
				block->fsb_nodes[i].fsn_fibre.f_stack,
				store->fs_stack_size);
		}

		SLIST_REMOVE_HEAD(&store->fs_blocks, fsb_blocks);
		mmap_deallocate(block, sizeof *block);
	}
}


void
fibre_finish(void)
{
	warnx("Deinitialising fibre system");

	warnx("Fibre stat stack_allocs: %ld", fibre_stats.fstat_stack_allocs);
	warnx("Fibre stat fibre_go_calls: %ld", fibre_stats.fstat_fibre_go_calls);
	warnx("Fibre stat iocalls: %ld", fibre_stats.fstat_iocalls);

	fibre_store_destroy(&global_fibre_store);
}

void
fibre_return(void)
{
	/* fprintf(stderr, "Returning from fibre %p\n", (void *)current_fibre); */

	if (current_fibre != main_fibre) {
		current_fibre->f_state = FS_EMPTY;
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
fibre_enqueue_ready(struct fibre *fibre)
{
	fibre->f_state = FS_READY;
	fibre_store_list_enqueue(
		&global_fibre_store.fs_lists[fibre->f_prio],
		fibre);
}

static
void
fibre_enqueue_waiting(struct fibre *fibre, int fd, int events)
{
	struct fibre_store_list *waiting
		= &global_fibre_store.fs_lists[FL_HIGH_WAITING + fibre->f_prio];
	struct epoll_event ev;

	ev.events = events;
	ev.data.ptr = container_of(struct fibre_store_node, fsn_fibre, fibre);

	fibre->f_state = FS_WAITING;
	fibre_store_list_enqueue(waiting, fibre);

	if (fibre->f_fd == fd) {
		if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_MOD, fibre->f_fd, &ev))
			err(EXIT_FAILURE, "epoll_ctl(EPOLL_CTL_MOD)");
		return;
	}

	if (fibre->f_fd != -1)
		if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_DEL, fibre->f_fd, NULL))
			err(EXIT_FAILURE, "epoll_ctl(EPOLL_CTL_DEL)");

	fibre->f_fd = fd;
	if (epoll_ctl(waiting->fsl_epfd, EPOLL_CTL_ADD, fibre->f_fd, &ev))
		err(EXIT_FAILURE, "epoll_ctl(EPOLL_CTL_ADD)");
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

static
int
fibre_yield_impl(int fd, int events)
{
	struct fibre_ctx *old, *new;
	struct fibre *old_fibre, *fibre;

	/* if BUILD_VALGRIND is false, this variable is unused */
	(void)old_fibre;

	if (current_fibre->f_state != FS_EMPTY) {
		if (fd != -1)
			fibre_enqueue_waiting(current_fibre, fd, events);
	}

	fibre = fibre_store_get_next_ready(&global_fibre_store);
	if (fibre == NULL) {
		/* fprintf(stderr, "Yielding from fibre %p, finishing\n", */
		/* 	(void *)current_fibre); */
		return 0;
	}

	if (current_fibre->f_state != FS_EMPTY) {
		if (fd == -1)
			fibre_enqueue_ready(current_fibre);
	}

	fibre->f_state = FS_ACTIVE;
	old = &current_fibre->f_ctx;
	new = &fibre->f_ctx;
	old_fibre = current_fibre;
	current_fibre = fibre;
	/* fprintf(stderr, "Yielding from fibre %d to fibre %d.\n", */
	/* 	   old_fibre->f_id, */
	/* 	   current_fibre->f_id); */
	fibre_switch(old, new);
	return 1;
}

int
fibre_awaitfd(int fd, int events)
{
	return fibre_yield_impl(fd, events);
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

	if (current_fibre->f_fd == fd)
		current_fibre->f_fd = -1;
}

int
fibre_yield(void)
{
	return fibre_yield_impl(-1, 0);
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
	current_fibre->f_func(current_fibre->f_datan, current_fibre->f_datap);
}

void
fibre_go(int prio, void (*func)(int, void *), int datan, void *datap)
{
	char *stack;
	size_t size = global_fibre_store.fs_stack_size;
	struct fibre *fibre = fibre_store_get_first_empty(&global_fibre_store);

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
	/* Obviously this doesn't actually work! OBVIOUSLY! We need to use an
	 * assembly function to put this pointer into rsi before the first call
	 * to this fibre.
	 *     fibre->f_ctx.rsi = (uint64_t)data;
	 */
	fibre->f_id = ++global_fibre_count;
	fibre->f_state = FS_READY;
	fibre->f_prio = prio;
	fibre->f_stack = stack;
	fibre->f_func = func;
	fibre->f_datap = datap;
	fibre->f_datan = datan;
	fibre_enqueue_ready(fibre);
}

static void *mmap_allocate(size_t m)
{
	void *p;

	p = mmap(NULL, m, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		/* MAP_GROWSDOWN|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); */
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "Failed to allocate (mmap)");
#ifdef BUILD_VALGRIND
	VALGRIND_MALLOCLIKE_BLOCK(p, m, 0, 1);
#endif
	return p;
}

static void  mmap_deallocate(void *p, size_t n)
{
	int r;

	r = munmap(p, n);
	if (r == -1)
		err(EXIT_FAILURE, "Failed to deallocate (munmap)");
#ifdef BUILD_VALGRIND
	VALGRIND_FREELIKE_BLOCK(p, 0);
#endif
}
