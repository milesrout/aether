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

struct peer {
	int                     status;
	struct sockaddr_storage addr;
	socklen_t               addr_len;
	char                    host[NI_MAXHOST];
	char                    service[NI_MAXSERV];
	uint64_t		hash;
	union packet_state      state;
};
enum peer_status {
	PEER_NEW,		/* the initial state of all peers */
	PEER_REPLIED,		/* we have replied to the peer's hello */
	PEER_ACTIVE,		/* the handshake is complete */
};
struct peer_init {
	struct sockaddr_storage addr;
	socklen_t               addr_len;
};
struct peertable {
	struct peer **table;
	size_t        tombs;
	size_t        size;
	size_t        cap;
};
extern int peertable_init(struct peertable *);
extern void peertable_finish(struct peertable *);
extern struct peer *peer_add(struct peertable *, const struct peer_init *);
extern struct peer *peer_getbyaddr(struct peertable *, const struct sockaddr *, socklen_t);
extern int peer_del(struct peertable *, struct peer *);
extern int peer_getnameinfo(struct peer *);
