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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

#include "monocypher.h"

#include "err.h"
#include "persist.h"
#include "util.h"

#include "lockedbuf.h"

void *
lockedbuf(void *p, size_t n)
{
	void *q;
	int fixed = p ? MAP_FIXED : 0;

	q = mmap(p, n, PROT_READ|PROT_WRITE,
		fixed|MAP_ANONYMOUS|MAP_PRIVATE|MAP_LOCKED, -1, 0);
	if (q == MAP_FAILED) {
		return NULL;
	}

	if (mlock(q, n)) {
		munmap(q, n);
		return NULL;
	}

	return q;
}
