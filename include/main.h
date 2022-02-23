struct p2pstate {
	struct key key;
	struct mesg_state state;
	const char *username;
};
extern void usage(void);
extern int alice(int argc, char **argv);
extern int bob(int argc, char **argv);
extern void interactive(struct ident_state *ident,
	struct mesg_state *state, struct p2pstate **p2ptable,
	int fd, uint8_t buf[65536]);
extern int register_identity(struct mesg_state *state, struct ident_state *ident,
	int fd, uint8_t buf[65536], const char *name);
