#include <linux/ioctl.h>

#define EOE_MAGIC 'E'
#define EOE_SETEUID _IOR(EOE_MAGIC, 1, int)
#define EOE_SETALL  _IO(EOE_MAGIC, 2)

#define MAXNAME 1000
#define EOE_MAJOR 127


#ifdef __KERNEL__
/* prototypes of device functions */
int add_program(struct pt_regs);
int exec_read(struct file*, char*, size_t, loff_t*);
int exec_ioctl(struct inode*, struct file*, unsigned int, unsigned long);
int exec_open(struct inode*, struct file*);
void exec_close(struct inode*, struct file*);


/* entry per program-execution */
struct executions {
	char *name;
	int uid, euid;
	struct executions *next;
};

/* the actual and last entry in execurion-list */
struct executions *act = NULL, 
                  *last = NULL;
                  
/* wait-queue for blockng read() */
struct wait_queue *wp = NULL;
#endif

