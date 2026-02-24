#if 0
void auth_encrypt_connect(void);
void auth_encrypt_init(void);
#endif

void Exit(int);
void ExitString(const char *, int);
int TerminalAutoFlush(void);
void TerminalDefaultChars(void);
int TerminalSpecialChars(int);
void TerminalSpeeds(long *ispeed, long *ospeed);
int TerminalWindowSize(long *rows, long *cols);
void auth_encrypt_user(char *);
void auth_name(unsigned char *, int);
void auth_printsub(unsigned char *, int, unsigned char *, int);
void cmdrc(const char *m1, const char *m2);
void env_init(void);
int getconnmode(void);
void init_network(void);
void init_sys(void);
void init_telnet(void);
void init_terminal(void);
int netflush(void);
void optionstatus(void);
int process_rings(int, int, int, int, int, int);
void quit(void);
int rlogin_susp(void);
int send_tncmd(int (*func)(int, int), const char *cmd, const char *name);
void sendeof(void);
void sendsusp(void);
void set_escape_char(char *);
void tel_leave_binary(int);
int telrcv(void);
int tn(int argc, const char *argv[]);
int ttyflush(int);
void sendayt(void);
void ayt_status(int);
void ayt(int sig);

/* commands.c */
void cmdtab_init(void);
