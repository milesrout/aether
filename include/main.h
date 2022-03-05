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
	struct packet_state state;
	const char *username;
};
extern void usage(void);
extern int alice(int argc, char **argv);
extern int bob(int argc, char **argv);
extern int interactive(struct ident_state *ident,
	struct packet_state *state, struct p2pstate **p2ptable,
	int fd, uint8_t buf[65536]);
extern int register_identity(struct ident_state *ident,
	struct packet_state *state,
	int fd, uint8_t buf[65536], const char *name);
