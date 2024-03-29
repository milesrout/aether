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
struct p2pstate {
	struct key key;
	union packet_state state;
	const char *username;
};
extern void usage(const char *, int);
extern int alice(char **, int);
extern int bob(char **, int);
extern void interactive(struct ident_state *ident, union packet_state *state,
	struct p2pstate **p2ptable, int fd);
extern int register_identity(struct ident_state *ident,
	union packet_state *state, int fd, uint8_t *buf, size_t bufsz,
	const char *name);
extern int prompt_line(char **buf, size_t *len, size_t *size,
	const char *prompt);
#define CLIENT_STACK_SIZE (80 * 1024L)
#define SERVER_STACK_SIZE (16 * 1024L)
