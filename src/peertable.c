#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"
#include "mesg.h"
#include "peertable.h"
#include "monocypher.h"

#define PEERTABLE_INIT_CAP 8

static struct peer tombstone;

int
peertable_init(struct peertable *pt)
{
	struct peer **table = calloc(PEERTABLE_INIT_CAP, sizeof *pt->table);
	if (table == NULL)
		return -1;

	pt->table = table;
	pt->tombs = 0;
	pt->size = 0;
	pt->cap = PEERTABLE_INIT_CAP;

	return 0;
}

void
peertable_finish(struct peertable *pt)
{
	if (pt->table) {
		free(pt->table);
	}
}

static
int
grow_peertable(struct peertable *pt)
{
	size_t newcap = pt->cap * 2;
	struct peer **new, **old = pt->table;
	size_t i;

	new = calloc(newcap, sizeof *pt->table);
	if (new == NULL)
		return -1;

	for (i = 0; i < pt->cap; i++) {
		if (old[i] && old[i] != &tombstone) {
			size_t idx = old[i]->hash % newcap;
			while (new[idx])
				idx = (idx + 1) % newcap;
			new[idx] = old[i];
		}
	}

	free(old);
	pt->table = new;
	pt->tombs = 0;
	pt->cap = newcap;

	return 0;
}

static
uint64_t
hash_peeraddr(const struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t hasharr[8];

	crypto_blake2b_general(hasharr, 8, NULL, 0,
		(const uint8_t *)addr, addr_len);

	return load64_le(hasharr);
}

/* If the table is more than 2/3 full or more than 1/3 of it is tombstones,
 * we should grow the table
 */
static
int
should_grow(struct peertable *pt)
{
	if (3 * pt->size > 2 * pt->cap)
		return 1;
	if (3 * pt->tombs > pt->cap)
		return 1;
	return 0;
}

struct peer *
peer_add(struct peertable *pt, const struct peer_init *pi)
{
	struct peer *peer;
	size_t idx;

	if (should_grow(pt))
		if (grow_peertable(pt))
			return NULL;

	peer = malloc(sizeof *peer);
	if (peer == NULL)
		return NULL;

	memcpy(&peer->addr, &pi->addr, pi->addr_len);
	peer->addr_len = pi->addr_len;
	peer->status = PEER_NEW;
	memset(&peer->state, 0, sizeof peer->state);
	peer->hash = hash_peeraddr((const struct sockaddr *)&pi->addr, pi->addr_len);
	idx = peer->hash % pt->cap;

	/* Should always find a free slot because we grow the table above if
	 * there isn't one
	 */
	while (pt->table[idx] && pt->table[idx] != &tombstone)
		idx = (idx + 1) % pt->cap;
	if (pt->table[idx] == &tombstone)
		pt->tombs--;
	pt->table[idx] = peer;
	pt->size++;

	return peer;
}

struct peer *
peer_getbyaddr(struct peertable *pt, const struct sockaddr *addr, socklen_t addr_len)
{
	uint64_t hash = hash_peeraddr(addr, addr_len);
	size_t idx = hash % pt->cap, i = idx;
	struct peer *p = pt->table[i];

	while (p != NULL) {
		if (p->hash == hash && p->addr.ss_family == addr->sa_family &&
				p->addr_len == addr_len &&
				memcmp(&p->addr, addr, addr_len) == 0)
			return p;
		i = (i + 1) % pt->cap;
		if (i == idx)
			break;
		p = pt->table[i];
	}

	return NULL;
}

int
peer_del(struct peertable *pt, struct peer *p)
{
	size_t i, idx = p->hash % pt->cap;

	for (i = idx; pt->table[i] != NULL && (pt->table[i]->hash % pt->cap) == idx; i++) {
		if (pt->table[i] == p) {
			pt->table[i] = &tombstone;
			pt->size--;
			pt->tombs++;
			return 0;
		}
		if (++i == idx)
			break;
	}

	return -1;
}
