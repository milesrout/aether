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

extern int fcntl_nonblock(int fd);
extern const char *safe_read(size_t *nread, int fd, uint8_t *buf, size_t size);
extern const char *safe_recvfrom(size_t *nread, int fd, uint8_t *buf, size_t size,
	struct sockaddr *peeraddr, socklen_t *peeraddr_len);
extern const char *safe_write(int fd, const uint8_t *buf, size_t size);
extern const char *safe_sendto(int fd, const uint8_t *buf, size_t size,
	struct sockaddr *peeraddr, socklen_t peeraddr_len);
extern int setclientup(const char *addr, const char *port);
