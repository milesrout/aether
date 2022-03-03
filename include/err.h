#include <err.h>
extern char *__progname;
#define errg(label, ...) do { warnx(__VA_ARGS__); goto label; } while (0)
