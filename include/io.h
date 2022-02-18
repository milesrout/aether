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

extern struct sockaddr *sstosa(struct sockaddr_storage *ss);
extern size_t safe_read(int fd, uint8_t *buf, size_t max_size_p1);
extern size_t safe_read_nonblock(int fd, uint8_t *buf, size_t max_size_p1);
extern size_t safe_read_timeout(int fd, uint8_t *buf, size_t max_size_p1, time_t timeout);
extern size_t safe_recvfrom(int fd, uint8_t *buf, size_t max_size_p1,
	struct sockaddr_storage *peeraddr, socklen_t *peeraddr_len);
extern void safe_write(int fd, const uint8_t *buf, size_t size);
extern void safe_sendto(int fd, const uint8_t *buf, size_t size,
	struct sockaddr *peeraddr, socklen_t peeraddr_len);
extern int setclientup(const char *addr, const char *port);
