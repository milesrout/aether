#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>

#include "err.h"
#include "fibre.h"

int
fibre_sleep_s(time_t seconds)
{
	struct timespec ts;

	ts.tv_sec = seconds;
	ts.tv_nsec = 0;

	return fibre_sleep(&ts);
}

int
fibre_sleep_ms(long milliseconds)
{
	struct timespec ts;

	ts.tv_sec = milliseconds / 1000L;
	ts.tv_nsec = (milliseconds % 1000L) * 1000000L;

	return fibre_sleep(&ts);
}

int
fibre_sleep_us(long microseconds)
{
	struct timespec ts;

	ts.tv_sec = microseconds / 1000000L;
	ts.tv_nsec = (microseconds % 1000000L) * 1000L;

	return fibre_sleep(&ts);
}

int
fibre_sleep_ns(long nanoseconds)
{
	struct timespec ts;

	ts.tv_sec = nanoseconds / 1000000000L;
	ts.tv_nsec = nanoseconds % 1000000000L;

	return fibre_sleep(&ts);
}

int
fibre_sleep(const struct timespec *duration)
{
	int fd, result;
	struct itimerspec timer;

	fd = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
	if (fd == -1)
		err(EXIT_FAILURE, "fibre_sleep: Could not create timerfd");

	timer.it_value.tv_sec = duration->tv_sec;
	timer.it_value.tv_nsec = duration->tv_nsec;
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_nsec = 0;
	if (timerfd_settime(fd, 0, &timer, NULL))
		err(EXIT_FAILURE, "fibre_sleep: Could not set timer on timerfd");

	result = fibre_awaitfd(fd, EPOLLIN);

	fibre_close(fd);

	return result;
}

