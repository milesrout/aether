#include <stdio.h>
#include <stdlib.h>
/* #include "stdio_impl.h" */
#include <string.h>
#include <inttypes.h>
#include <errno.h>

char *sgetdelim(FILE *f, size_t *len, int delim,
		char *stack, size_t stacksz,
		char **heap, size_t *heapsz);

char *sgetdelim(FILE *f, size_t *len, int delim,
		char *stack, size_t stacksz,
		char **heap, size_t *heapsz)
{
	char *tmp, *str = stack;
	size_t i = 0;
	int c;

	if (!f || !len || !heap || !heapsz) {
		errno = EINVAL;
		return NULL;
	}

	if (!*heap) *heapsz = 0;

	flockfile(f);

	for (;;) {
		if (i == stacksz) {
			if (*heapsz <= stacksz) {
				*heapsz = 2 * (i + 2);
				tmp = realloc(*heap, *heapsz);
				if (!tmp) goto oom;
				*heap = tmp;
			}
			memcpy(*heap, stack, stacksz);
			str = *heap;
		} else if (i == *heapsz) {
			*heapsz = 2 * (i + 2);
			tmp = realloc(*heap, *heapsz);
			if (!tmp) goto oom;
			str = *heap = tmp;
		}
		if ((c = getc_unlocked(f)) == EOF) {
			if (!i || !feof(f)) {
				funlockfile(f);
				return NULL;
			}
			break;
		}
		if ((str[i++] = c) == delim) break;
	}
	str[i] = 0;

	funlockfile(f);

	*len = i;
	return str;

oom:
	funlockfile(f);
	errno = ENOMEM;
	return NULL;
}
