#define PROGRAM		"kkfun"
#define AUTHOR		"palmers / teso"


#define MODULE
#define __KERNEL__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/config.h>
#include <linux/pc_keyb.h>
#include <linux/proc_fs.h>
#include <asm/unistd.h>
#include <asm/keyboard.h>
#include <linux/interrupt.h>
#include <asm/softirq.h>

#include "options.h"
#include "convert.h"


#define copy_from_user  __generic_copy_from_user
#define copy_to_user    __generic_copy_to_user

