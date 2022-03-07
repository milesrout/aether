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

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
	if (fd == -1)
		err(EXIT_FAILURE, "Could not create fd");

	timer.it_value = ts;
	timer.it_interval = ts;

	if (timerfd_settime(fd, 0, &timer, NULL))
		err(EXIT_FAILURE, "Could not set timer");

	return fd;
}
