#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/timerfd.h>

#include "err.h"
#include "util.h"
#include "fibre.h"

#ifdef BUILD_VALGRIND
#include <valgrind/valgrind.h>
#endif

#include "fibre_switch.h"

static void *mmap_allocate(size_t m);
static void  mmap_deallocate(void *p, size_t n);
static void *mmap_reallocate(void *q, size_t m, size_t n);

static struct {
	long int fstat_stack_allocs;
	long int fstat_fibre_go_calls;
} fibre_stats = {0};

/*
 * This structure represents an execution context, namely it contains the
 * values for all callee-saved registers, and the stack pointer. Because we
 * switch fibres using a function call, the compiler takes care of saving
 * everything else.
 *
 * This struct will need to be extended with additional items over time. For
 * example, if/when fibre-local storage is implemented, there will need to be
 * pointer in this structure to that storage.
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

enum fibre_prio {
	/* a fibre used for ui or other interactive functionality */
	FP_HIGH,
	/* any other fibre */
	FP_NORMAL,
	/* a fibre used for non-latency-sensitive background tasks */
	FP_BACKGROUND,
	/* number of priorities */
	FP_NUM_PRIOS
};

enum fibre_list {
	FL_HIGH,
	FL_NORMAL,
	FL_BACKGROUND,
	FL_HIGH_WAITING,
	FL_NORMAL_WAITING,
	FL_BACKGROUND_WAITING,
	FL_EMPTY,
	FL_NUM_LISTS
};
#define FL_NUM_ACTIVE (FL_BACKGROUND + 1)

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
#ifdef BUILD_VALGRIND
	unsigned f_valgrind_id;
#else
	unsigned reserved[1];
#endif
	int f_id;
	int f_fd;
	int f_poll;
	char *f_stack;
	void (*f_func)(void *);
	void *f_data;
};

static
void
fibre_setup(struct fibre *fibre)
{
	/* f_ctx is invalid when f_state = EMPTY */
	fibre->f_state = FS_EMPTY;
	/* f_prio is invalid when f_state = EMPTY */
	/* f_valgrind_id is initialised when needed */
	/* f_id is invalid when f_state = EMPTY */
	/* f_fd is valid only when f_state = WAITING */
	/* f_poll is valid only when f_state = WAITING */
	fibre->f_stack = NULL;
	/* f_func is invalid when f_state = EMPTY */
	/* f_data is invalid when f_state = EMPTY */
}

/*
 * This is a node in an intrusive bidirectional linked list of struct fibres.
 */
struct fibre_store_node {
	struct fibre_store_node *fsn_prev, *fsn_next;
	struct fibre fsn_fibre;
};

/*
 * This is the control block for a linked list of struct fibres.
 * it has two valid states:
 *   fsl_start===NULL & fsl_end===NULL -> list is empty
 *   fsl_start=/=NULL & fsl_end=/=NULL -> list is non-empty
 */
struct fibre_store_list {
	struct fibre_store_node *fsl_start, *fsl_end;
	int fsl_count;
};

static
void
fibre_store_list_init(struct fibre_store_list *list)
{
	list->fsl_start = list->fsl_end = NULL;
	list->fsl_count = 0;
}

/* adds a fibre to the start of the list */
static
void
fibre_store_list_enqueue(struct fibre_store_list *list, struct fibre *fibre)
{
	struct fibre_store_node *node =
		container_of(struct fibre_store_node, fsn_fibre, fibre);

	/* require that the fibre is not already in a list */
	assert(node->fsn_next == NULL);
	assert(node->fsn_prev == NULL);

	if (list->fsl_start == NULL || list->fsl_end == NULL) {
		assert(list->fsl_start == NULL);
		assert(list->fsl_end == NULL);

		list->fsl_start = node;
		list->fsl_end = node;
	} else if (list->fsl_start == list->fsl_end) {
		assert(list->fsl_start->fsn_prev == NULL);
		assert(list->fsl_end->fsn_next == NULL);
		
		list->fsl_start = node;
		node->fsn_next = list->fsl_end;
		list->fsl_end->fsn_prev = node;

		assert(list->fsl_start != list->fsl_end);
		assert(list->fsl_start != NULL);
		assert(list->fsl_end != NULL);
		assert(list->fsl_start->fsn_next == list->fsl_end);
		assert(list->fsl_end->fsn_prev == list->fsl_start);
		assert(list->fsl_start->fsn_prev == NULL);
		assert(list->fsl_end->fsn_next == NULL);
	} else {
		assert(list->fsl_start != NULL);
		assert(list->fsl_end != NULL);
		assert(list->fsl_start->fsn_prev == NULL);
		assert(list->fsl_end->fsn_next == NULL);

		list->fsl_start->fsn_prev = node;
		node->fsn_next = list->fsl_start;
		list->fsl_start = node;
	}

	list->fsl_count++;
}

/* removes a fibre from the end of the list */
static
struct fibre *
try_fibre_store_list_dequeue(struct fibre_store_list *list)
{
	struct fibre_store_node *node;

	if (list->fsl_start == NULL || list->fsl_end == NULL) {
		assert(list->fsl_start == NULL);
		assert(list->fsl_end == NULL);

		return NULL;
	}

	/* require that the list is non-empty */
	assert(list->fsl_start != NULL);
	assert(list->fsl_end != NULL);

	/* these should just generally be true of *every* list */
	assert(list->fsl_start->fsn_prev == NULL);
	assert(list->fsl_end->fsn_next == NULL);

	node = list->fsl_end;
	if (list->fsl_start == list->fsl_end) {
		assert(node->fsn_prev == NULL);
		assert(node->fsn_next == NULL);
		list->fsl_start = list->fsl_end = NULL;
		list->fsl_count--;
		assert(list->fsl_count == 0);
	} else {
		if (node->fsn_prev == NULL) {
			assert(list->fsl_end == list->fsl_start);
			list->fsl_start = list->fsl_end = NULL;
		} else {
			assert(list->fsl_end != list->fsl_start);
			node->fsn_prev->fsn_next = NULL;
			list->fsl_end = node->fsn_prev;
			node->fsn_prev = NULL;
		}

		list->fsl_count--;
	}
	return &node->fsn_fibre;
}

/*
 * This value is calculated so that each fibre_store_block should be page-sized.
 * e.g. if sizeof(fibre_store_node) is 160 bytes, this value should be 25.
 */
#define FIBRE_STORE_NODES_PER_BLOCK 34

/*
 * struct fibres are allocated in page-sized blocks, which at the moment are
 * never deallocated, but the struct fibres within them can be reused.
 */
struct fibre_store_block {
	struct fibre_store_block *fsb_next;
	struct fibre_store_node fsb_nodes[FIBRE_STORE_NODES_PER_BLOCK];
};

/*
 * there is a list of ready fibres for each priority level plus a list of
 * empty fibres.
 */
struct fibre_store {
	size_t fs_stack_size;
	struct fibre_store_block *fs_blocks;
	/* the last list is for FS_EMPTY fibres */
	struct fibre_store_list fs_lists[FL_NUM_LISTS];
};

static
struct fibre_store_block *
fibre_store_block_create(struct fibre_store *store)
{
	struct fibre_store_block *block =
		mmap_allocate(sizeof *block);
	size_t i;

#define MAX (FIBRE_STORE_NODES_PER_BLOCK - 1)
	/* set up the nodes in the block to form a bidirectional linked list */
	for (i = 0; i <= MAX; i++) {
		block->fsb_nodes[i].fsn_prev = (i == 0) ? NULL : &block->fsb_nodes[i - 1];
		block->fsb_nodes[i].fsn_next = (i == MAX) ? NULL : &block->fsb_nodes[i + 1];
		fibre_setup(&block->fsb_nodes[i].fsn_fibre);
	}
#undef MAX
	
	block->fsb_next = store->fs_blocks;
	store->fs_blocks = block;

	return block;
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

	/* count not used for list of empties */
	/* assert(empties_list->fsl_count == 0); */

	if (empties_list->fsl_start == NULL || empties_list->fsl_end == NULL) {
		struct fibre_store_block *block;

		assert(empties_list->fsl_start == NULL);
		assert(empties_list->fsl_end == NULL);

		block = fibre_store_block_create(store);
		empties_list->fsl_start = &block->fsb_nodes[0];
		empties_list->fsl_end =
			&block->fsb_nodes[FIBRE_STORE_NODES_PER_BLOCK - 1];
	}

	/* assert that the list is non-empty */
	assert(empties_list->fsl_start != NULL);
	assert(empties_list->fsl_end != NULL);

	/* these should just generally be true of *every* list */
	assert(empties_list->fsl_start->fsn_prev == NULL);
	assert(empties_list->fsl_end->fsn_next == NULL);

	node = empties_list->fsl_start;

	if (node->fsn_next == NULL) {
		assert(empties_list->fsl_end == empties_list->fsl_start);
		empties_list->fsl_start = empties_list->fsl_end = NULL;
	} else {
		assert(empties_list->fsl_end != empties_list->fsl_start);
		node->fsn_next->fsn_prev = NULL;
		empties_list->fsl_start = node->fsn_next;
		node->fsn_next = NULL;
	}

	return &node->fsn_fibre;
}

static
int
fibre_store_poll(int timeout, struct fibre_store_list *ready, struct fibre_store_list *waiting)
{
	struct pollfd *pfds;
	struct fibre_store_node *node, *next;
	int i, pcount;

	pfds = malloc(sizeof(struct pollfd) * waiting->fsl_count);
	if (pfds == NULL)
		err(EXIT_FAILURE, "Could not allocate poll fd array");

	for (i = 0, node = waiting->fsl_start;
			node != NULL;
			i++, node = node->fsn_next) {
		assert(i < waiting->fsl_count);
		assert(node != NULL);
		pfds[i].fd = node->fsn_fibre.f_fd;
		pfds[i].events = node->fsn_fibre.f_poll;
	}
	assert(i == waiting->fsl_count);
	assert(node == NULL);

	pcount = poll(pfds, waiting->fsl_count, timeout);
	if (pcount == -1)
		err(EXIT_FAILURE, "Could not poll");
	if (pcount == 0) {
		free(pfds);
		return 0;
	}

	for (i = 0, node = waiting->fsl_start, next = node->fsn_next;
			node != NULL;
			i++, node = next) {
		next = node->fsn_next;
		if (pfds[i].revents) {
			if (node->fsn_prev) {
				node->fsn_prev->fsn_next = node->fsn_next;
			}
			if (node->fsn_next) {
				node->fsn_next->fsn_prev = node->fsn_prev;
			}
			if (node == waiting->fsl_start) {
				assert(node->fsn_prev == NULL);
				waiting->fsl_start = node->fsn_next;
			}
			if (node == waiting->fsl_end) {
				assert(node->fsn_next == NULL);
				waiting->fsl_end = node->fsn_prev;
			}
			node->fsn_prev = NULL;
			node->fsn_next = NULL;
			if (ready->fsl_start == NULL || ready->fsl_end == NULL) {
				assert(ready->fsl_start == NULL);
				assert(ready->fsl_end == NULL);
				ready->fsl_start = ready->fsl_end = node;
				node->fsn_prev = node->fsn_next = NULL;
			} else {
				assert(ready->fsl_start != NULL);
				assert(ready->fsl_end != NULL);

				ready->fsl_end->fsn_next = node;
				node->fsn_prev = ready->fsl_end;
				ready->fsl_end = node;
				node->fsn_next = NULL;
			}
			waiting->fsl_count--;
			ready->fsl_count++;
			node->fsn_fibre.f_state = FS_READY;
		}
	}

	free(pfds);
	return 1;
}

static
struct fibre *
fibre_store_get_next_ready(struct fibre_store *store, int timeout)
{
	struct fibre *fibre;
	size_t i;

	for (i = 0; i < FP_NUM_PRIOS; i++) {
		if (store->fs_lists[FL_HIGH_WAITING + i].fsl_count &&
				fibre_store_poll(timeout, &store->fs_lists[i],
					&store->fs_lists[FL_HIGH_WAITING + i])) {
			/* return try_fibre_store_list_dequeue(&store->fs_lists[i]); */
		}
		if ((fibre = try_fibre_store_list_dequeue(&store->fs_lists[i])) != NULL)
			return fibre;
	}

	return NULL;
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
	size_t i;

	warnx("Initialising fibre system with %luKiB-sized stacks",
		stack_size / 1024);

#define BLOCK_SIZE (sizeof(struct fibre_store_block))
#define NODE_SIZE (sizeof(struct fibre_store_node))
	if (BLOCK_SIZE > page_size)
		warnx("fibre_store_block is too big to fit in a page: lower FIBRE_STORE_NODES_PER_BLOCK (%lu)",
			BLOCK_SIZE);
	else if (BLOCK_SIZE + NODE_SIZE <= page_size)
		warnx("fibre_store_block could be bigger: raise FIBRE_STORE_NODES_PER_BLOCK (%lu)",
			BLOCK_SIZE);
	else
		warnx("fibre_store_block fits perfectly in a page (%lu)",
			BLOCK_SIZE);
#undef BLOCK_SIZE
#undef NODE_SIZE

	global_fibre_store.fs_stack_size = stack_size;
	global_fibre_store.fs_blocks = NULL;

	for (i = 0; i < FL_NUM_LISTS; i++)
		fibre_store_list_init(&global_fibre_store.fs_lists[i]);

	main_fibre = fibre_store_get_first_empty(&global_fibre_store);
	main_fibre->f_state = FS_ACTIVE;
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
	size_t i;
	while (store->fs_blocks != NULL) {
		struct fibre_store_block *next = store->fs_blocks->fsb_next;
		for (i = 0; i < FIBRE_STORE_NODES_PER_BLOCK; i++) {
			if (&store->fs_blocks->fsb_nodes[i].fsn_fibre == main_fibre)
				continue;
			if (store->fs_blocks->fsb_nodes[i].fsn_fibre.f_stack == NULL)
				continue;
			mmap_deallocate(
				store->fs_blocks->fsb_nodes[i].fsn_fibre.f_stack,
				store->fs_stack_size);
		}
		mmap_deallocate(
			store->fs_blocks,
			sizeof *store->fs_blocks);
		store->fs_blocks = next;
	}
}


void
fibre_finish(void)
{
	warnx("Deinitialising fibre system");

	warnx("Fibre stat stack_allocs: %ld", fibre_stats.fstat_stack_allocs);
	warnx("Fibre stat fibre_go_calls: %ld", fibre_stats.fstat_fibre_go_calls);

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
	fibre_store_list_enqueue(
		&global_fibre_store.fs_lists[fibre->f_prio],
		fibre);
}

static
void
fibre_enqueue_waiting(struct fibre *fibre)
{
	fibre_store_list_enqueue(
		&global_fibre_store.fs_lists[FL_HIGH_WAITING + fibre->f_prio],
		fibre);
}

static int fibre_yield_impl(int plain);

int
fibre_sleep(const struct timespec *duration)
{
	int fd, res, result;
	struct itimerspec timer;

	fd = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
	if (fd == -1)
		err(EXIT_FAILURE, "Could not create timerfd");

	timer.it_value.tv_sec = duration->tv_sec;
	timer.it_value.tv_nsec = duration->tv_nsec;
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_nsec = 0;
	res = timerfd_settime(fd, 0, &timer, NULL);
	if (res == -1)
		err(EXIT_FAILURE, "Could not set timer");

	current_fibre->f_fd = fd;
	current_fibre->f_poll = POLLIN;
	current_fibre->f_state = FS_WAITING;
	fibre_enqueue_waiting(current_fibre);
	result = fibre_yield_impl(0);

	{
		int res;

		res = close(fd);
		if (res == -1)
			err(EXIT_FAILURE, "Could not close");

		return res;
	}
}

int
fibre_yield(void)
{
	return fibre_yield_impl(1);
}

static
int
fibre_yield_impl(int plain)
{
	struct fibre_ctx *old, *new;
	struct fibre *old_fibre;
	struct fibre *fibre = fibre_store_get_next_ready(&global_fibre_store, 0);

	if (fibre == NULL) {
		/* fprintf(stderr, "Yielding from fibre %p, finishing\n", */
		/*                    (void *)current_fibre); */
		fibre = fibre_store_get_next_ready(&global_fibre_store, -1);
		if (fibre == NULL)
			return 0;
	}

	if (plain) {
		if (current_fibre->f_state != FS_EMPTY) {
			current_fibre->f_state = FS_READY;
			fibre_enqueue_ready(current_fibre);
		}
	}
	fibre->f_state = FS_ACTIVE;
	old = &current_fibre->f_ctx;
	new = &fibre->f_ctx;
	old_fibre = current_fibre;
	current_fibre = fibre;
	/* fprintf(stderr, "Yielding from fibre %p to fibre %p.\n", */
	/*                    (void *)old_fibre, */
	/*                    (void *)current_fibre); */
#ifdef BUILD_VALGRIND
	current_fibre->f_valgrind_id = VALGRIND_STACK_REGISTER(
		current_fibre->f_stack,
		current_fibre->f_stack + global_fibre_store.fs_stack_size);
#endif
	fibre_switch(old, new);
#ifdef BUILD_VALGRIND
	VALGRIND_STACK_DEREGISTER(old_fibre->f_valgrind_id);
#endif
	return 1;
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
	current_fibre->f_func(current_fibre->f_data);
}

void
fibre_go(void (*func)(void *), void *data)
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
	fibre->f_prio = FP_NORMAL;
	fibre->f_stack = stack;
	fibre->f_func = func;
	fibre->f_data = data;
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

static void *mmap_reallocate(void *q, size_t m, size_t n)
{
	void *p;

	p = mremap(q, m, n, MREMAP_MAYMOVE);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "Failed to reallocate (mremap)");
#ifdef BUILD_VALGRIND
	if (p == q)
		VALGRIND_RESIZEINPLACE_BLOCK(p, m, n, 0);
	else {
		VALGRIND_FREELIKE_BLOCK(p, 0);
		VALGRIND_MALLOCLIKE_BLOCK(p, n, 0, 1);
	}
#endif

	return p;
}