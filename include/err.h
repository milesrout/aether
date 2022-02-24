#include <err.h>
extern char *__progname;
#define errg(...) do { warnx(__VA_ARGS__); goto fail; } while (0)
