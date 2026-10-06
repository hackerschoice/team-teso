/*
 * Copyright (C) 1999/2000 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*! \file eoe.h
 *  \brief include file for the EoE driver.
 *  All programs, using EoE must include this file.
 */

/*!  \version 2.32
 */

#include <linux/ioctl.h>


#define EOE_MAGIC 'E'

/*! \def EOE_SETEUID
 *  \brief The ioctl() command to change the euid to monitor.
 */
#define EOE_SETEUID _IOR(EOE_MAGIC, 1, int)

/*! \def EOE_SETALL 
 *  \brief The ioctl() command to monitor all euids.
 */
#define EOE_SETALL  _IO(EOE_MAGIC, 2)

#define MAXNAME 1000
#define EOE_MAJOR 127


#ifdef __KERNEL__

/* prototypes of device functions */
int add_program(unsigned long, unsigned long);
int exec_read(struct file*, char*, size_t, loff_t*);
int exec_ioctl(struct inode*, struct file*, unsigned int, unsigned long);
int exec_open(struct inode*, struct file*);
void exec_close(struct inode*, struct file*);


/*! \struct executions 
 *  \brief One entry per program-execution.
 */
struct executions {
	char *name;
	int uid, euid, pid;
	char p_comm[16];
	struct executions *next;
};

/*! The actual and last entry in execution-list.
 */
struct executions *act = NULL, 
                  *last = NULL;
                  
/*! wait-queue for blockng read() 
 */
struct wait_queue *wp = NULL;
#endif

