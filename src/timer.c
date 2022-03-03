#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>

#include "fibre.h"
#include "timer.h"

int
timerfd_open(struct timespec ts)
{
	int fd;
	struct itimerspec timer;

	fd = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
	if (fd == -1)
		err(EXIT_FAILURE, "Could not create fd");

	timer.it_value = ts;
	timer.it_interval = ts;

	if (timerfd_settime(fd, 0, &timer, NULL))
		err(EXIT_FAILURE, "Could not set timer");

	return fd;
}
